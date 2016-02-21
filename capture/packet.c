/* packet.c  -- Functions for acquiring data
 *
 * Copyright 2012-2016 AOL Inc. All rights reserved.
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

#define __FAVOR_BSD
#include "moloch.h"
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

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
extern MolochSessionHead_t   tcpWriteQ[MOLOCH_MAX_PACKET_THREADS];

static MolochPacketHead_t    packetQ[MOLOCH_MAX_PACKET_THREADS];


MolochSession_t *moloch_packet_ip4(MolochPacket_t * const packet, const uint8_t *data, int len);

/******************************************************************************/
void moloch_packet_free(MolochPacket_t *packet)
{
    if (packet->notSaved) 
        moloch_writer_null_finish(packet);
    else
        moloch_writer_finish(packet);
    MOLOCH_TYPE_FREE(MolochPacket_t, packet);
}
/******************************************************************************/
void moloch_packet_tcp_free(MolochSession_t *session)
{
    MolochTcpData_t *td;
    while (DLL_POP_HEAD(td_, &session->tcpData, td)) {
        moloch_packet_free(td->packet);
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
LOCAL void moloch_packet_tcp_finish(MolochSession_t *session)
{
    MolochTcpData_t            *ftd;
    MolochTcpData_t            *next;

    MolochTcpDataHead_t * const tcpData = &session->tcpData;

    DLL_FOREACH_REMOVABLE(td_, tcpData, ftd, next) {
        const int which = ftd->packet->direction;
        const uint32_t tcpSeq = session->tcpSeq[which];

        if (tcpSeq >= ftd->seq && tcpSeq < (ftd->seq + ftd->len)) {
            const int offset = tcpSeq - ftd->seq;
            const uint8_t *data = ftd->packet->pkt + ftd->dataOffset + offset;
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
            moloch_packet_free(ftd->packet);
            MOLOCH_TYPE_FREE(MolochTcpData_t, ftd);
        } else {
            return;
        }
    }
}

/******************************************************************************/
LOCAL void moloch_packet_process_icmp(MolochSession_t * const UNUSED(session), MolochPacket_t * const UNUSED(packet))
{
}
/******************************************************************************/
LOCAL void moloch_packet_process_udp(MolochSession_t * const session, MolochPacket_t * const packet)
{
    const uint8_t *data = packet->pkt + packet->payloadOffset + 8;
    int            len = packet->payloadLen - 8;

    if (len <= 0)
        return;

    if (session->firstBytesLen[packet->direction] == 0) {
        session->firstBytesLen[packet->direction] = MIN(8, len);
        memcpy(session->firstBytes[packet->direction], data, session->firstBytesLen[packet->direction]);

        if (!session->stopSPI)
            moloch_parsers_classify_udp(session, data, len, packet->direction);
    }
}
/******************************************************************************/
LOCAL int moloch_packet_process_tcp(MolochSession_t * const session, MolochPacket_t * const packet)
{
    if (session->stopSPI || session->stopTCP)
        return 1;


    struct tcphdr       *tcphdr = (struct tcphdr *)(packet->pkt + packet->payloadOffset);


    int            len = packet->payloadLen - 4*tcphdr->th_off;

    const uint32_t seq = ntohl(tcphdr->th_seq);

    if (len < 0)
        return 1;

    if (tcphdr->th_flags & TH_SYN) {
        session->haveTcpSession = 1;
        session->tcpSeq[packet->direction] = seq + 1;
        if (!session->tcp_next) {
            DLL_PUSH_TAIL(tcp_, &tcpWriteQ[session->thread], session);
        }
        return 1;
    }

    if (tcphdr->th_flags & TH_RST) {
        if (moloch_packet_sequence_diff(seq, session->tcpSeq[packet->direction]) <= 0) {
            return 1;
        }

        session->tcpState[packet->direction] = MOLOCH_TCP_STATE_FIN_ACK;
    }

    if (tcphdr->th_flags & TH_FIN) {
        session->tcpState[packet->direction] = MOLOCH_TCP_STATE_FIN;
    }

    MolochTcpDataHead_t * const tcpData = &session->tcpData;

    if (DLL_COUNT(td_, tcpData) > 256) {
        moloch_packet_tcp_free(session);
        moloch_session_add_tag(session, "incomplete-tcp");
        session->stopTCP = 1;
        return 1;
    }

    if (tcphdr->th_flags & (TH_ACK | TH_RST)) {
        int owhich = (packet->direction + 1) & 1;
        if (session->tcpState[owhich] == MOLOCH_TCP_STATE_FIN) {
            session->tcpState[owhich] = MOLOCH_TCP_STATE_FIN_ACK;
            if (session->tcpState[packet->direction] == MOLOCH_TCP_STATE_FIN_ACK) {

                if (!session->closingQ) {
                    moloch_session_mark_for_close(session, SESSION_TCP);
                }
                return 1;
            }
        }
    }

    // Empty packet, drop from tcp processing
    if (len <= 0 || tcphdr->th_flags & TH_RST)
        return 1;

    // This packet is before what we are processing
    int32_t diff = moloch_packet_sequence_diff(session->tcpSeq[packet->direction], seq + len);
    if (diff <= 0)
        return 1;

    MolochTcpData_t *ftd, *td = MOLOCH_TYPE_ALLOC(MolochTcpData_t);
    const uint32_t ack = ntohl(tcphdr->th_ack);

    td->packet = packet;
    td->ack = ack;
    td->seq = seq;
    td->len = len;
    td->dataOffset = packet->payloadOffset + 4*tcphdr->th_off;

    if (DLL_COUNT(td_, tcpData) == 0) {
        DLL_PUSH_TAIL(td_, tcpData, td);
    } else {
        uint32_t sortA, sortB;
        DLL_FOREACH_REVERSE(td_, tcpData, ftd) {
            if (packet->direction == ftd->packet->direction) {
                sortA = seq;
                sortB = ftd->seq;
            } else {
                sortA = seq;
                sortB = ftd->ack;
            }

            diff = moloch_packet_sequence_diff(sortB, sortA);
            if (diff == 0) {
                if (packet->direction == ftd->packet->direction) {
                    if (td->len > ftd->len) {
                        DLL_ADD_AFTER(td_, tcpData, ftd, td);

                        DLL_REMOVE(td_, tcpData, ftd);
                        moloch_packet_free(packet);
                        MOLOCH_TYPE_FREE(MolochTcpData_t, ftd);
                        ftd = td;
                    } else {
                        MOLOCH_TYPE_FREE(MolochTcpData_t, td);
                        return 1;
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

    return 0;
}

/******************************************************************************/
void moloch_packet_thread_wake(int thread)
{
    MOLOCH_COND_BROADCAST(packetQ[thread].lock);
}
/******************************************************************************/
/* Only called on main thread, we busy block until all packet threads are empty.
 * Should only be used by tests and at end
 */
void moloch_packet_flush()
{
    int flushed = 0;
    int t;
    while (!flushed) {
        flushed = 1;
        for (t = 0; t < config.packetThreads; t++) {
            MOLOCH_LOCK(packetQ[t].lock);
            if (DLL_COUNT(packet_, &packetQ[t]) > 0) {
                flushed = 0;
            }
            MOLOCH_UNLOCK(packetQ[t].lock);
            usleep(10000);
        }
    }
}
/******************************************************************************/
LOCAL void *moloch_packet_thread(void *threadp)
{
    MolochSession_t *session;
    MolochPacket_t  *packet;
    int thread = (long)threadp;

    while (1) {
        MOLOCH_LOCK(packetQ[thread].lock);
        if (DLL_COUNT(packet_, &packetQ[thread]) == 0) {
            MOLOCH_COND_WAIT(packetQ[thread].lock);
        }
        DLL_POP_HEAD(packet_, &packetQ[thread], packet);
        MOLOCH_UNLOCK(packetQ[thread].lock);

        moloch_session_process_commands(thread);

        if (!packet)
            continue;

        session = moloch_session_find(packet->ses, packet->sessionId);

        int freePacket = 1;

        if (!session) {
            LOG("ALW - shouldn't be new session %d - %p", thread, packet);
            goto cleanup;
        }

        if (pcapFileHeader.linktype == 1 && session->firstBytesLen[packet->direction] < 8) {
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

            if (packet->direction == 1) {
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

        if (!packet->notSaved) {
            int16_t len;
            if (session->lastFileNum != packet->writerFileNum) {
                session->lastFileNum = packet->writerFileNum;
                g_array_append_val(session->fileNumArray, packet->writerFileNum);
                int64_t pos = -1LL * packet->writerFileNum;
                g_array_append_val(session->filePosArray, pos);
                len = 0;
                g_array_append_val(session->fileLenArray, len);
            }

            g_array_append_val(session->filePosArray, packet->writerFilePos);
            len = 16 + packet->pktlen;
            g_array_append_val(session->fileLenArray, len);

            if (session->filePosArray->len - session->fileNumArray->len >= config.maxPackets) {
                moloch_session_mid_save(session, packet->ts.tv_sec);
            }
        }

        switch(packet->ses) {
        case SESSION_ICMP:
            moloch_packet_process_icmp(session, packet);
            break;
        case SESSION_UDP:
            moloch_packet_process_udp(session, packet);
            break;
        case SESSION_TCP:
            freePacket = moloch_packet_process_tcp(session, packet);
            moloch_packet_tcp_finish(session);
            break;
        }

cleanup:
        if (freePacket) {
            moloch_packet_free(packet);
        }
    }

    return NULL;
}

/******************************************************************************/
void moloch_packet_gre4(MolochPacket_t * const packet, const struct ip *ip4, const uint8_t *data, int len)
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
MolochSession_t *moloch_packet_ip4(MolochPacket_t * const packet, const uint8_t *data, int len)
{
    struct ip           *ip4 = (struct ip*)data;
    struct tcphdr       *tcphdr = 0;
    struct udphdr       *udphdr = 0;

    if (len < (int)sizeof(struct ip))
        goto cleanup;

    int ip_len = ntohs(ip4->ip_len);
    if (len < ip_len)
        goto cleanup;

    int ip_hdr_len = 4 * ip4->ip_hl;
    if (len < ip_hdr_len)
        goto cleanup;

    switch (ip4->ip_p) {
    case IPPROTO_TCP:
        if (len < ip_hdr_len + (int)sizeof(struct tcphdr)) {
            goto cleanup;
        }

        tcphdr = (struct tcphdr *)((char*)ip4 + ip_hdr_len);

        moloch_session_id(packet->sessionId, ip4->ip_src.s_addr, tcphdr->th_sport,
                          ip4->ip_dst.s_addr, tcphdr->th_dport);
        packet->ses = SESSION_TCP;
        packet->payloadOffset = (uint8_t*)tcphdr - packet->pkt;
        break;
    case IPPROTO_UDP:
        if (len < ip_hdr_len + (int)sizeof(struct udphdr)) {
            goto cleanup;
        }

        udphdr = (struct udphdr *)((char*)ip4 + ip_hdr_len);

        moloch_session_id(packet->sessionId, ip4->ip_src.s_addr, udphdr->uh_sport,
                          ip4->ip_dst.s_addr, udphdr->uh_dport);
        packet->ses = SESSION_UDP;
        packet->payloadOffset = (uint8_t*)udphdr - packet->pkt;
        break;
    case IPPROTO_ICMP:
        moloch_session_id(packet->sessionId, ip4->ip_src.s_addr, 0,
                          ip4->ip_dst.s_addr, 0);
        packet->ses = SESSION_ICMP;
        packet->payloadOffset = (uint8_t*)ip4 - packet->pkt;
        break;
    case IPPROTO_GRE:
        moloch_packet_gre4(packet, ip4, data + ip_hdr_len, len - ip_hdr_len);
        goto cleanup;
    default:
        if (config.logUnknownProtocols)
            LOG("Unknown protocol %d", ip4->ip_p);
        goto cleanup;
    }

    packet->payloadLen = ip_len - ip_hdr_len;

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

        LOG("packets: %" PRIu64 " current sessions: %u/%u oldest: %d - recv: %" PRIu64 " drop: %" PRIu64 " (%0.2f) queue: %d disk: %d tfq: %d close: %d",
          totalPackets,
          moloch_session_watch_count(packet->ses),
          moloch_session_monitoring(),
          moloch_session_idle_seconds(packet->ses),
          stats.total,
          stats.dropped - initialDropped,
          (stats.dropped - initialDropped)*(double)100.0/stats.total,
          moloch_http_queue_length(esServer),
          moloch_writer_queue_length(),
          moloch_packet_outstanding(),
          moloch_session_close_outstanding()
          );
    }


    MolochSession_t *session;

    int isNew;
    session = moloch_session_find_or_create(packet->ses, packet->sessionId, &isNew); // Returns locked session

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
            if (moloch_http_is_moloch(session->h_hash, packet->sessionId)) {
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

    packet->direction = 0;
    switch (ip4->ip_p) {
    case IPPROTO_UDP:
        packet->direction = (session->addr1 == ip4->ip_src.s_addr &&
                             session->addr2 == ip4->ip_dst.s_addr &&
                             session->port1 == ntohs(udphdr->uh_sport) &&
                             session->port2 == ntohs(udphdr->uh_dport))?0:1;
        session->databytes[packet->direction] += (packet->pktlen - 8);
        break;
    case IPPROTO_TCP:
        packet->direction = (session->addr1 == ip4->ip_src.s_addr &&
                             session->addr2 == ip4->ip_dst.s_addr &&
                             session->port1 == ntohs(tcphdr->th_sport) &&
                             session->port2 == ntohs(tcphdr->th_dport))?0:1;
        session->tcp_flags |= tcphdr->th_flags;
        break;
    case IPPROTO_ICMP:
        packet->direction = (session->addr1 == ip4->ip_src.s_addr &&
                             session->addr2 == ip4->ip_dst.s_addr)?0:1;
        break;
    }

    /* Check if the stop saving bpf filters match */
    if (session->packets[packet->direction] == 0 && session->stopSaving == 0 && config.dontSaveBPFsNum) {
        int i = moloch_reader_should_filter(packet);
        if (i >= 0)
            session->stopSaving = config.dontSaveBPFsStop[i];
    }

    session->packets[packet->direction]++;
    session->bytes[packet->direction] += packet->pktlen;
    session->lastPacket = packet->ts;

    uint32_t packets = session->packets[0] + session->packets[1];

    if (session->stopSaving == 0 || packets < session->stopSaving) {
        moloch_writer_write(packet);
    } else {
        packet->notSaved = 1;
        moloch_writer_null_write(packet);
    }

    session->thread = session->h_hash % config.packetThreads;
    MOLOCH_LOCK(packetQ[session->thread].lock);
    DLL_PUSH_TAIL(packet_, &packetQ[session->thread], packet);
    MOLOCH_UNLOCK(packetQ[session->thread].lock);
    MOLOCH_COND_BROADCAST(packetQ[session->thread].lock);

    return session;
cleanup:
    MOLOCH_TYPE_FREE(MolochPacket_t, packet);
    return NULL;
}

#ifdef FOO
{
    uint16_t ip_off = ntohs(ip4->ip_off);
    uint16_t ip_flags = ip_off & ~IP_OFFMASK;
    ip_off &= IP_OFFMASK;
    if (ip_flags & IP_MF) {
        moloch_session_add_tag(session, "frag-flag");
    }
    if (ip_off > 0) {
        moloch_session_add_tag(session, "frag-off");
    }



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

    return session;
}
#endif
/******************************************************************************/
void moloch_packet_ip6(MolochPacket_t * const UNUSED(packet), const uint8_t *data, int len)
{
    data = 0;
    len = 0;
}
/******************************************************************************/
void moloch_packet_ether(MolochPacket_t * const packet, const uint8_t *data, int len)
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
void moloch_packet(MolochPacket_t * const packet)
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
    int count = 0;
    int t;

    for (t = 0; t < config.packetThreads; t++) {
        count += DLL_COUNT(packet_, &packetQ[t]);
    }
    return count;
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
        MOLOCH_FIELD_TYPE_IP_GHASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);

    int t;
    for (t = 0; t < config.packetThreads; t++) {
        char name[100];
        snprintf(name, sizeof(name), "moloch-pkt%d", t);
        g_thread_new(name, &moloch_packet_thread, (gpointer)(long)t);
        DLL_INIT(packet_, &packetQ[t]);
        MOLOCH_LOCK_INIT(packetQ[t].lock);
        MOLOCH_COND_INIT(packetQ[t].lock);
    }

    moloch_add_can_quit(moloch_packet_outstanding);
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
