/* packet.c  -- Functions for acquiring data
 *
 * Copyright 2012-2015 AOL Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this Software except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "moloch.h"

/******************************************************************************/
extern MolochConfig_t        config;

MolochPcapFileHdr_t          pcapFileHeader;

uint64_t                     totalPackets = 0;
uint64_t                     totalBytes = 0;
uint64_t                     totalSessions = 0;

static uint32_t              initialDropped = 0;
struct timeval               initialPacket;

extern void                 *esServer;
extern uint32_t              pluginsCbs;

static int                   mac1Field;
static int                   mac2Field;
static int                   vlanField;
static int                   greIpField;

time_t                       lastPacketSecs;

/******************************************************************************/
extern MolochSessionHead_t   tcpWriteQ;
extern MOLOCH_LOCK_EXTERN(tcpWriteQ);

static MolochSessionHead_t   tcpFinishQ;

static MOLOCH_LOCK_DEFINE(tcpFinishQ);
static MOLOCH_COND_DEFINE(tcpFinishQ);


MolochSession_t *moloch_packet_ip4(const MolochPacket_t *packet, const uint8_t *data, int len);

/******************************************************************************/
// session should already be locked
void moloch_packet_process_udp(MolochSession_t *session, struct udphdr *UNUSED(udphdr), unsigned char *data, int len, int which)
{
    if (len <= 0)
        return;

    if (session->firstBytesLen[which] == 0) {
        session->firstBytesLen[which] = MIN(8, len);
        memcpy(session->firstBytes[which], data, session->firstBytesLen[which]);

        if (!session->stopSPI)
            moloch_parsers_classify_udp(session, data, len, which);
    }
}
/******************************************************************************/
void moloch_packet_tcp_free(MolochSession_t *session)
{
    MolochTcpData_t *td;
    while (DLL_POP_HEAD(td_, &session->tcpData, td)) {
        free(td->data);
        MOLOCH_TYPE_FREE(MolochTcpData_t, td);
    }
}
/******************************************************************************/
// Idea from gopacket tcpassembly/assemply.go
LOCAL int32_t moloch_packet_sequence_diff (uint32_t a, uint32_t b)
{
    if (a > 0xc0000000 && b < 0x40000000)
        return (a + 0xffffffffLL - b);

    if (b > 0xc0000000 && a < 0x40000000)
        return (a - b - 0xffffffffLL);

    return b - a;
}
/******************************************************************************/
// session should already be locked
LOCAL void moloch_packet_tcp_finish(MolochSession_t *session)
{
    MolochTcpData_t            *ftd;
    MolochTcpData_t            *next;

    MolochTcpDataHead_t * const tcpData = &session->tcpData;

    DLL_FOREACH_REMOVABLE(td_, tcpData, ftd, next) {
        const int which = ftd->which;
        const uint32_t tcpSeq = session->tcpSeq[which];

        if (tcpSeq >= ftd->seq && tcpSeq < (ftd->seq + ftd->len)) {
            const int offset = tcpSeq - ftd->seq;
            const uint8_t *data = ftd->data + offset;
            const int len = ftd->len - offset;

            if (session->firstBytesLen[which] < 8) {
                int copy = MIN(8 - session->firstBytesLen[which], len);
                memcpy(session->firstBytes[which] + session->firstBytesLen[which], data, copy);
                session->firstBytesLen[which] += copy;
            }

            if (session->totalDatabytes[which] == session->consumed[which])  {
                moloch_parsers_classify_tcp(session, data, len, which);
            }

            int i;
            int totConsumed = 0;
            int consumed = 0;

            for (i = 0; i < session->parserNum; i++) {
                if (session->parserInfo[i].parserFunc) {
                    consumed = session->parserInfo[i].parserFunc(session, session->parserInfo[i].uw, data, len, which);
                    if (consumed) {
                        totConsumed += consumed;
                        session->consumed[which] += consumed;
                    }

                    if (consumed >= len)
                        break;
                }
            }
            session->tcpSeq[which] += len;
            session->databytes[which] += len;
            session->totalDatabytes[which] += len;

            if (config.yara) {
                moloch_yara_execute(session, data, len, 0);
            }

            DLL_REMOVE(td_, tcpData, ftd);
            free(ftd->data);
            MOLOCH_TYPE_FREE(MolochTcpData_t, ftd);
        } else {
            return;
        }
    }
}
/******************************************************************************/
LOCAL void *moloch_packet_tcp_thread(void *UNUSED(unused))
{
    MolochSession_t *session;

    while (1) {
        MOLOCH_LOCK(tcpFinishQ);
        while (DLL_COUNT(tfq_, &tcpFinishQ) == 0) {
            MOLOCH_COND_WAIT(tcpFinishQ);
        }
        session = DLL_PEEK_HEAD(tfq_, &tcpFinishQ);
        if (MOLOCH_SESSION_TRYLOCK) {
            DLL_POP_HEAD(tfq_, &tcpFinishQ, session);
            MOLOCH_UNLOCK(tcpFinishQ);
            moloch_packet_tcp_finish(session);
            MOLOCH_SESSION_UNLOCK;
        } else {
            MOLOCH_UNLOCK(tcpFinishQ);
        }
    }

    return NULL;
}
/******************************************************************************/
// session should already be locked
LOCAL void moloch_packet_process_tcp(MolochSession_t *session, struct tcphdr *tcphdr, unsigned char *data, int len, const int which)
{
    if (session->stopSPI || session->stopTCP)
        return;

    if (len < 0)
        return;

    const uint32_t seq = ntohl(tcphdr->th_seq);

    if (tcphdr->th_flags & TH_SYN) {
        session->haveTcpSession = 1;
        session->tcpSeq[which] = seq + 1;
        if (!session->tcp_next) {
            MOLOCH_LOCK(tcpWriteQ);
            DLL_PUSH_TAIL(tcp_, &tcpWriteQ, session);
            MOLOCH_UNLOCK(tcpWriteQ);
        }
        return;
    }

    if (tcphdr->th_flags & TH_RST) {
        if (moloch_packet_sequence_diff(seq, session->tcpSeq[which]) <= 0) {
            return;
        }

        session->tcpState[which] = MOLOCH_TCP_STATE_FIN_ACK;
    }

    if (tcphdr->th_flags & TH_FIN) {
        session->tcpState[which] = MOLOCH_TCP_STATE_FIN;
    }

    MolochTcpDataHead_t * const tcpData = &session->tcpData;

    if (DLL_COUNT(td_, tcpData) > 256) {
        moloch_packet_tcp_free(session);
        moloch_session_add_tag(session, "incomplete-tcp");
        session->stopTCP = 1;
        return;
    }

    if (tcphdr->th_flags & (TH_ACK | TH_RST)) {
        int owhich = (which + 1) & 1;
        if (session->tcpState[owhich] == MOLOCH_TCP_STATE_FIN) {
            session->tcpState[owhich] = MOLOCH_TCP_STATE_FIN_ACK;
            if (session->tcpState[which] == MOLOCH_TCP_STATE_FIN_ACK) {

                if (!session->closingQ) {
                    moloch_session_mark_for_close(session, SESSION_TCP);
                }
                return;
            }
        }
    }

    // Empty packet, drop from tcp processing
    if (len <= 0 || tcphdr->th_flags & TH_RST)
        return;

    // This packet is before what we are processing
    int32_t diff = moloch_packet_sequence_diff(session->tcpSeq[which], seq + len);
    if (diff <= 0)
        return;

    MolochTcpData_t *ftd, *td = MOLOCH_TYPE_ALLOC(MolochTcpData_t);
    const uint32_t ack = ntohl(tcphdr->th_ack);

    td->ack = ack;
    td->seq = seq;
    td->len = len;
    td->which = which;

    if (DLL_COUNT(td_, tcpData) == 0) {
        DLL_PUSH_TAIL(td_, tcpData, td);
    } else {
        uint32_t sortA, sortB;
        DLL_FOREACH_REVERSE(td_, tcpData, ftd) {
            if (which == ftd->which) {
                sortA = seq;
                sortB = ftd->seq;
            } else {
                sortA = seq;
                sortB = ftd->ack;
            }

            diff = moloch_packet_sequence_diff(sortB, sortA);
            if (diff == 0) {
                if (which == ftd->which) {
                    if (td->len > ftd->len) {
                        DLL_ADD_AFTER(td_, tcpData, ftd, td);

                        DLL_REMOVE(td_, tcpData, ftd);
                        free(ftd->data);
                        MOLOCH_TYPE_FREE(MolochTcpData_t, ftd);
                        ftd = td;
                    } else {
                        MOLOCH_TYPE_FREE(MolochTcpData_t, td);
                        return;
                    }
                    break;
                } else if (moloch_packet_sequence_diff(ack, ftd->seq) < 0) {
                    DLL_ADD_AFTER(td_, tcpData, ftd, td);
                    break;
                }
            } else if (diff > 0) {
                DLL_ADD_AFTER(td_, tcpData, ftd, td);
                break;
            }
        }
        if ((void*)ftd == (void*)tcpData) {
            DLL_PUSH_HEAD(td_, tcpData, td);
        }
    }

    // Don't dup the data until actually added
    td->data = g_memdup(data, len);

    if (!session->tfq_next) {
        MOLOCH_LOCK(tcpFinishQ);
        DLL_PUSH_TAIL(tfq_, &tcpFinishQ, session);
        MOLOCH_UNLOCK(tcpFinishQ);
        MOLOCH_COND_BROADCAST(tcpFinishQ);
    }
}
/******************************************************************************/
void moloch_packet_gre4(const MolochPacket_t *packet, const struct ip *ip4, const uint8_t *data, int len)
{
    BSB bsb;

    if (len < 4)
        return;

    BSB_INIT(bsb, data, len);
    uint16_t flags_version = 0;
    BSB_IMPORT_u16(bsb, flags_version);
    uint16_t type = 0;
    BSB_IMPORT_u16(bsb, type);

    if (type != 0x0800) {
        if (config.logUnknownProtocols)
            LOG("Unknown GRE protocol 0x%04x(%d)", type, type);
        return;
    }

    uint16_t offset = 0;

    if (flags_version & (0x8000 | 0x4000)) {
        BSB_IMPORT_skip(bsb, 2);
        BSB_IMPORT_u16(bsb, offset);
    }

    // key
    if (flags_version & 0x2000) {
        BSB_IMPORT_skip(bsb, 4);
    }

    // sequence number
    if (flags_version & 0x1000) {
        BSB_IMPORT_skip(bsb, 4);
    }

    // routing
    if (flags_version & 0x4000) {
        while (BSB_NOT_ERROR(bsb)) {
            BSB_IMPORT_skip(bsb, 3);
            int len = 0;
            BSB_IMPORT_u08(bsb, len);
            if (len == 0)
                break;
            BSB_IMPORT_skip(bsb, len);
        }
    }

    if (BSB_NOT_ERROR(bsb)) {
        MolochSession_t *session = moloch_packet_ip4(packet, BSB_WORK_PTR(bsb), BSB_REMAINING(bsb));
        if (!session)
            return;

        moloch_field_int_add(greIpField, session, ip4->ip_src.s_addr);
        moloch_field_int_add(greIpField, session, ip4->ip_dst.s_addr);
        moloch_session_add_protocol(session, "gre");
    }


}
/******************************************************************************/
// ALW TODO: IP FRAGS!!!
MolochSession_t *moloch_packet_ip4(const MolochPacket_t *packet, const uint8_t *data, int len)
{
    struct ip           *ip4 = (struct ip*)data;
    char                 sessionId[MOLOCH_SESSIONID_LEN];
    struct tcphdr       *tcphdr = 0;
    struct udphdr       *udphdr = 0;
    int                  ses;

    if (len < (int)sizeof(struct ip))
        return NULL;

    int ip_len = ntohs(ip4->ip_len);
    if (len < ip_len)
        return NULL;

    int ip_hdr_len = 4 * ip4->ip_hl;
    if (len < ip_hdr_len)
        return NULL;

    switch (ip4->ip_p) {
    case IPPROTO_TCP:
        if (len < ip_hdr_len + (int)sizeof(struct tcphdr)) {
            return NULL;
        }

        tcphdr = (struct tcphdr *)((char*)ip4 + ip_hdr_len);

        moloch_session_id(sessionId, ip4->ip_src.s_addr, tcphdr->th_sport,
                          ip4->ip_dst.s_addr, tcphdr->th_dport);
        ses = SESSION_TCP;
        break;
    case IPPROTO_UDP:
        if (len < ip_hdr_len + (int)sizeof(struct udphdr)) {
            return NULL;
        }

        udphdr = (struct udphdr *)((char*)ip4 + ip_hdr_len);

        moloch_session_id(sessionId, ip4->ip_src.s_addr, udphdr->uh_sport,
                          ip4->ip_dst.s_addr, udphdr->uh_dport);
        ses = SESSION_UDP;
        break;
    case IPPROTO_ICMP:
        moloch_session_id(sessionId, ip4->ip_src.s_addr, 0,
                          ip4->ip_dst.s_addr, 0);
        ses = SESSION_ICMP;
        break;
    case IPPROTO_GRE:
        moloch_packet_gre4(packet, ip4, data + ip_hdr_len, len - ip_hdr_len);
        return NULL;
    default:
        if (config.logUnknownProtocols)
            LOG("Unknown protocol %d", ip4->ip_p);
        return NULL;
    }

    totalBytes += packet->pktlen;
    lastPacketSecs = packet->ts.tv_sec;

    if (totalPackets == 0) {
        MolochReaderStats_t stats;
        if (!moloch_reader_stats(&stats)) {
            initialDropped = stats.dropped;
        }
        initialPacket = packet->ts;
        LOG("Initial Packet = %ld", initialPacket.tv_sec);
        LOG("%" PRIu64 " Initial Dropped = %d", totalPackets, initialDropped);
    }

    if ((++totalPackets) % config.logEveryXPackets == 0) {
        MolochReaderStats_t stats;
        if (moloch_reader_stats(&stats)) {
            stats.dropped = 0;
            stats.total = totalPackets;
        }

        LOG("packets: %" PRIu64 " current sessions: %u/%u oldest: %d - recv: %" PRIu64 " drop: %" PRIu64 " (%0.2f) queue: %d disk: %d tfq: %d close: %d magic: %d",
          totalPackets,
          moloch_session_watch_count(ses),
          moloch_session_monitoring(),
          moloch_session_idle_seconds(ses),
          stats.total,
          stats.dropped - initialDropped,
          (stats.dropped - initialDropped)*(double)100.0/stats.total,
          moloch_http_queue_length(esServer),
          moloch_writer_queue_length(),
          moloch_packet_outstanding(),
          moloch_session_close_outstanding(),
          moloch_parsers_magic_outstanding()
          );
    }


    MolochSession_t *session;

    int isNew;
    session = moloch_session_find_or_create(ses, sessionId, &isNew); // Returns locked session

    if (isNew) {
        session->protocol = ip4->ip_p;
        session->saveTime = packet->ts.tv_sec + config.tcpSaveTimeout;
        session->firstPacket = packet->ts;
        session->addr1 = ip4->ip_src.s_addr;
        session->addr2 = ip4->ip_dst.s_addr;
        session->ip_tos = ip4->ip_tos;

        moloch_parsers_initial_tag(session);

        switch (ip4->ip_p) {
        case IPPROTO_TCP:
           /* If antiSynDrop option is set to true, capture will assume that
            *if the syn-ack ip4 was captured first then the syn probably got dropped.*/
            if ((tcphdr->th_flags & TH_SYN) && (tcphdr->th_flags & TH_ACK) && (config.antiSynDrop)) {
                session->addr1 = ip4->ip_dst.s_addr;
                session->addr2 = ip4->ip_src.s_addr;
                session->port1 = ntohs(tcphdr->th_dport);
                session->port2 = ntohs(tcphdr->th_sport);
            } else {
                session->port1 = ntohs(tcphdr->th_sport);
                session->port2 = ntohs(tcphdr->th_dport);
            }
            if (moloch_http_is_moloch(session->h_hash, sessionId)) {
                if (config.debug)
                    LOG("Ignoring connection %s", moloch_session_id_string(session->protocol, session->addr1, session->port1, session->addr2, session->port2));
                session->stopSPI = 1;
                session->stopSaving = 1;
            }
            break;
        case IPPROTO_UDP:
            session->port1 = ntohs(udphdr->uh_sport);
            session->port2 = ntohs(udphdr->uh_dport);
            break;
        case IPPROTO_ICMP:
            session->port1 = 0;
            session->port2 = 0;
            break;
        }

        if (pluginsCbs & MOLOCH_PLUGIN_NEW)
            moloch_plugins_cb_new(session);
    }

    uint16_t ip_off = ntohs(ip4->ip_off);
    uint16_t ip_flags = ip_off & ~IP_OFFMASK;
    ip_off &= IP_OFFMASK;
    if (ip_flags & IP_MF) {
        moloch_session_add_tag(session, "frag-flag");
    }
    if (ip_off > 0) {
        moloch_session_add_tag(session, "frag-off");
    }

    int which = 0;
    switch (ip4->ip_p) {
    case IPPROTO_UDP:
        which = (session->addr1 == ip4->ip_src.s_addr &&
                 session->addr2 == ip4->ip_dst.s_addr &&
                 session->port1 == ntohs(udphdr->uh_sport) &&
                 session->port2 == ntohs(udphdr->uh_dport))?0:1;
        session->databytes[which] += (packet->pktlen - 8);
        break;
    case IPPROTO_TCP:
        which = (session->addr1 == ip4->ip_src.s_addr &&
                 session->addr2 == ip4->ip_dst.s_addr &&
                 session->port1 == ntohs(tcphdr->th_sport) &&
                 session->port2 == ntohs(tcphdr->th_dport))?0:1;
        session->tcp_flags |= tcphdr->th_flags;
        break;
    case IPPROTO_ICMP:
        which = (session->addr1 == ip4->ip_src.s_addr &&
                 session->addr2 == ip4->ip_dst.s_addr)?0:1;
        break;
    }

    /* Handle MACs and vlans on first few packets in each direction */
    if (pcapFileHeader.linktype == 1 && session->packets[which] <= 1) {
        const uint8_t *pcapData = packet->pkt;
        char str1[20];
        char str2[20];
        snprintf(str1, sizeof(str1), "%02x:%02x:%02x:%02x:%02x:%02x",
                pcapData[0],
                pcapData[1],
                pcapData[2],
                pcapData[3],
                pcapData[4],
                pcapData[5]);


        snprintf(str2, sizeof(str2), "%02x:%02x:%02x:%02x:%02x:%02x",
                pcapData[6],
                pcapData[7],
                pcapData[8],
                pcapData[9],
                pcapData[10],
                pcapData[11]);

        if (which == 1) {
            moloch_field_string_add(mac1Field, session, str1, 17, TRUE);
            moloch_field_string_add(mac2Field, session, str2, 17, TRUE);
        } else {
            moloch_field_string_add(mac1Field, session, str2, 17, TRUE);
            moloch_field_string_add(mac2Field, session, str1, 17, TRUE);
        }

        int n = 12;
        while (pcapData[n] == 0x81 && pcapData[n+1] == 0x00) {
            uint16_t vlan = ((uint16_t)(pcapData[n+2] << 8 | pcapData[n+3])) & 0xfff;
            moloch_field_int_add(vlanField, session, vlan);
            n += 4;
        }
    }

    /* Check if the stop saving bpf filters match */
    if (session->packets[which] == 0 && session->stopSaving == 0 && config.dontSaveBPFsNum) {
        int i = moloch_reader_should_filter(packet);
        if (i >= 0)
            session->stopSaving = config.dontSaveBPFsStop[i];
    }

    session->bytes[which] += packet->pktlen;
    session->lastPacket = packet->ts;

    if (pluginsCbs & MOLOCH_PLUGIN_IP)
        moloch_plugins_cb_ip(session, ip4, len);

    session->packets[which]++;
    uint32_t packets = session->packets[0] + session->packets[1];

    if (session->stopSaving == 0 || packets < session->stopSaving) {
        uint32_t fileNum;
        uint64_t filePos;
        uint16_t fileLen = 16 + packet->pktlen;

        moloch_writer_write(packet, &fileNum, &filePos);

        if (session->lastFileNum != fileNum) {
            session->lastFileNum = fileNum;
            g_array_append_val(session->fileNumArray, fileNum);
            int64_t pos = -1LL * fileNum;
            g_array_append_val(session->filePosArray, pos);
            int16_t len = 0;
            g_array_append_val(session->fileLenArray, len);
        }

        g_array_append_val(session->filePosArray, filePos);
        g_array_append_val(session->fileLenArray, fileLen);

        if (packets >= config.maxPackets) {
            moloch_session_mid_save(session, packet->ts.tv_sec);
        }
    }


    /* Call any callbacks */
    switch (ip4->ip_p) {
    case IPPROTO_UDP:
        moloch_packet_process_udp(session, udphdr, (unsigned char*)udphdr+8, ip_len - ip_hdr_len - 8, which);
        break;
    case IPPROTO_TCP:
        moloch_packet_process_tcp(session, tcphdr, (unsigned char*)tcphdr + 4*tcphdr->th_off, ip_len - ip_hdr_len - 4 * tcphdr->th_off, which);
        break;
    }

    MOLOCH_SESSION_UNLOCK;
    return session;
}
/******************************************************************************/
void moloch_packet_ip6(const MolochPacket_t *packet, const uint8_t *data, int len)
{
    packet = 0;
    data = 0;
    len = 0;
}
/******************************************************************************/
void moloch_packet_ether(const MolochPacket_t *packet, const uint8_t *data, int len)
{
    if (len < 14) {
        return;
    }
    int n = 12;
    while (n+2 < len) {
        int ethertype = data[n] << 8 | data[n+1];
        n += 2;
        switch (ethertype) {
        case 0x0800:
            moloch_packet_ip4(packet, data+n, len - n);
            return;
        case 0x86dd:
            moloch_packet_ip6(packet, data+n, len - n);
            return;
        case 0x8100:
            n += 2;
            break;
        default:
            return;
        } // switch
    }
}
/******************************************************************************/
void moloch_packet(const MolochPacket_t *packet)
{
    switch(pcapFileHeader.linktype) {
    case 0: // NULL
        if (packet->pktlen > 4)
            moloch_packet_ip4(packet, packet->pkt+4, packet->pktlen-4);
        break;
    case 1: // Ether
        moloch_packet_ether(packet, packet->pkt, packet->pktlen);
        break;
    case 12: // RAw
        moloch_packet_ip4(packet, packet->pkt, packet->pktlen);
        break;
    case 113: // SLL
        moloch_packet_ip4(packet, packet->pkt, packet->pktlen);
        break;
    default:
        LOG("ERROR - Unsupported pcap link type %d", pcapFileHeader.linktype);
        exit (0);
    }
}
/******************************************************************************/
int moloch_packet_outstanding()
{
    return DLL_COUNT(tfq_, &tcpFinishQ);
}
/******************************************************************************/
void moloch_packet_init()
{
    pcapFileHeader.magic = 0xa1b2c3d4;
    pcapFileHeader.version_major = 2;
    pcapFileHeader.version_minor = 4;

    pcapFileHeader.thiszone = 0;
    pcapFileHeader.sigfigs = 0;

    mac1Field = moloch_field_define("general", "lotermfield",
        "mac.src", "Src MAC", "mac1-term",
        "Source ethernet mac addresses set for session",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT | MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
        NULL);

    mac2Field = moloch_field_define("general", "lotermfield",
        "mac.dst", "Dst MAC", "mac2-term",
        "Destination ethernet mac addresses set for session",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT | MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
        NULL);

    moloch_field_define("general", "lotermfield",
        "mac", "Src or Dst MAC", "macall",
        "Shorthand for mac.src or mac.dst",
        0,  MOLOCH_FIELD_FLAG_FAKE,
        "regex", "^mac\\\\.(?:(?!\\\\.cnt$).)*$",
        NULL);

    vlanField = moloch_field_define("general", "integer",
        "vlan", "VLan", "vlan",
        "vlan value",
        MOLOCH_FIELD_TYPE_INT_HASH,  MOLOCH_FIELD_FLAG_COUNT | MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
        NULL);

    greIpField = moloch_field_define("general", "ip",
        "gre.ip", "GRE IP", "greip",
        "GRE ip addresses for session",
        MOLOCH_FIELD_TYPE_IP_HASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);

    int i;
    for (i = 0; i < config.tcpThreads; i++) {
        char name[100];
        snprintf(name, sizeof(name), "moloch-tcp%d", i);
        g_thread_new(name, &moloch_packet_tcp_thread, NULL);
    }

    moloch_add_can_quit(moloch_packet_outstanding);
    DLL_INIT(tfq_, &tcpFinishQ);
}
/******************************************************************************/
uint32_t moloch_packet_dropped_packets()
{
    MolochReaderStats_t stats;
    if (moloch_reader_stats(&stats)) {
        return 0;
    }
    return stats.dropped - initialDropped;
}
/******************************************************************************/
void moloch_packet_exit()
{
}
