/* reader-pfring.c  -- pfring instead of libpcap
 *
 *  Simple plugin that queries the wise service for
 *  ips, domains, email, and md5s which can use various
 *  services to return data.  It caches all the results.
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

#include "moloch.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pfring.h>

extern MolochConfig_t        config;
extern MolochPcapFileHdr_t   pcapFileHeader;

LOCAL pfring *ring;

/******************************************************************************/
int reader_pfring_stats(MolochReaderStats_t *stats)
{
    pfring_stat pfstats;

    pfring_stats(ring, &pfstats);
    stats->dropped = pfstats.drop;
    stats->total = pfstats.recv;
    return 0;
}
/******************************************************************************/
void reader_pfring_packet_cb(const struct pfring_pkthdr *h, const u_char *p, const u_char *UNUSED(user_bytes))
{
    if (unlikely(h->caplen != h->len)) {
        LOG("ERROR - Moloch requires full packet captures caplen: %d pktlen: %d", h->caplen, h->len);
        exit (0);
    }

    MolochPacket_t *packet = MOLOCH_TYPE_ALLOC0(MolochPacket_t);

    packet->pkt           = (u_char *)p,
    packet->ts            = h->ts,
    packet->pktlen        = h->len,

    moloch_packet(packet);
}
/******************************************************************************/
static void *reader_pfring_thread()
{
    while (1) {
        int r = pfring_loop(ring, reader_pfring_packet_cb, NULL, -1);

        // Some kind of failure we quit
        if (unlikely(r <= 0)) {
            moloch_quit();
            ring = 0;
            break;
        }
    }
    return NULL;
}
/******************************************************************************/
void reader_pfring_start() {
    int dlt_to_linktype(int dlt);

    pcapFileHeader.linktype = 1;
    pcapFileHeader.snaplen = 16384;

/*
    if (config.dontSaveBPFs) {
        int i;
        if (bpf_programs) {
            for (i = 0; i < config.dontSaveBPFsNum; i++) {
                pcap_freecode(&bpf_programs[i]);
            }
        } else {
            bpf_programs= malloc(config.dontSaveBPFsNum*sizeof(struct bpf_program));
        }
        for (i = 0; i < config.dontSaveBPFsNum; i++) {
            if (pcap_compile(pcap, &bpf_programs[i], config.dontSaveBPFs[i], 0, PCAP_NETMASK_UNKNOWN) == -1) {
                LOG("ERROR - Couldn't compile filter: '%s' with %s", config.dontSaveBPFs[i], pcap_geterr(pcap));
                exit(1);
            }
        }
    }
*/

    g_thread_new("moloch-pcap", &reader_pfring_thread, NULL);
}
/******************************************************************************/
void reader_pfring_stop() 
{
    if (ring)
        pfring_breakloop(ring);
}
/******************************************************************************/
int reader_pfring_should_filter(const MolochPacket_t *UNUSED(packet))
{
/*    if (bpf_programs) {
        int i;
        for (i = 0; i < config.dontSaveBPFsNum; i++) {
            if (bpf_filter(bpf_programs[i].bf_insns, packet->pkt, packet->pktlen, packet->pktlen)) {
                return i;
                break;
            }
        }
    }*/
    return -1;
}
/******************************************************************************/
void reader_pfring_init(char *UNUSED(name))
{
    int flags = PF_RING_PROMISC | PF_RING_TIMESTAMP;

    ring = pfring_open(config.interface, 16384, flags);

    int clusterId = moloch_config_int(NULL, "pfringClusterId", 0, 0, 255);

    if (!ring) {
        LOG("pfring open failed!");
        exit(1);
    }

    pfring_set_cluster(ring, clusterId, cluster_per_flow_5_tuple);
    pfring_set_application_name(ring, "moloch-capture");
    pfring_set_poll_watermark(ring, 64);
    pfring_enable_rss_rehash(ring);

    moloch_reader_start         = reader_pfring_start;
    moloch_reader_stop          = reader_pfring_stop;
    moloch_reader_stats         = reader_pfring_stats;
    moloch_reader_should_filter = reader_pfring_should_filter;
}
/******************************************************************************/
void moloch_plugin_init()
{
    moloch_readers_add("pfring", reader_pfring_init);
}
