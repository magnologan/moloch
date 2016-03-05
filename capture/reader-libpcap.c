/******************************************************************************/
/* reader-libpcap-file.c  -- Reader using libpcap to a file
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
#define _FILE_OFFSET_BITS 64
#include "moloch.h"
#include <errno.h>
#include <sys/stat.h>
#include <gio/gio.h>
#include "pcap.h"

extern MolochPcapFileHdr_t   pcapFileHeader;

extern MolochConfig_t        config;

static pcap_t               *pcap;

static struct bpf_program   *bpf_programs = 0;

/******************************************************************************/
int reader_libpcap_stats(MolochReaderStats_t *stats)
{
    struct pcap_stat ps;
    if (unlikely(!pcap))
        return -1;
    int rc = pcap_stats (pcap, &ps);
    if (unlikely(rc))
        return rc;
    stats->dropped = ps.ps_drop;
    stats->total = ps.ps_recv;
    return 0;
}
/******************************************************************************/
void reader_libpcap_pcap_cb(u_char *UNUSED(user), const struct pcap_pkthdr *h, const u_char *bytes)
{
    if (unlikely(h->caplen != h->len)) {
        LOG("ERROR - Moloch requires full packet captures caplen: %d pktlen: %d", h->caplen, h->len);
        exit (0);
    }

    MolochPacket_t *packet = MOLOCH_TYPE_ALLOC0(MolochPacket_t);

    packet->pkt           = (u_char *)bytes,
    packet->ts            = h->ts,
    packet->pktlen        = h->len,

    moloch_packet(packet);
}
/******************************************************************************/
static void *reader_libpcap_thread()
{
    LOG("THREAD %p", (gpointer)pthread_self());

    while (1) {
        int r = pcap_loop(pcap, -1, reader_libpcap_pcap_cb, NULL);

        // Some kind of failure we quit
        if (unlikely(r <= 0)) {
            moloch_quit();
            pcap = 0;
            break;
        }
    }
    //ALW - Need to close after packet finishes
    //pcap_close(pcap);
    return NULL;
}
/******************************************************************************/
void reader_libpcap_start() {
    int dlt_to_linktype(int dlt);

    pcapFileHeader.linktype = dlt_to_linktype(pcap_datalink(pcap)) | pcap_datalink_ext(pcap);
    pcapFileHeader.snaplen = pcap_snapshot(pcap);

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

    if (config.bpf) {
        struct bpf_program   bpf;

        if (pcap_compile(pcap, &bpf, config.bpf, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            LOG("ERROR - Couldn't compile filter: '%s' with %s", config.bpf, pcap_geterr(pcap));
            exit(1);
        }

	if (pcap_setfilter(pcap, &bpf) == -1) {
            LOG("ERROR - Couldn't set filter: '%s' with %s", config.bpf, pcap_geterr(pcap));
            exit(1);
        }
    }

    g_thread_new("moloch-pcap", &reader_libpcap_thread, NULL);
}
/******************************************************************************/
void reader_libpcap_stop() 
{
    if (pcap)
        pcap_breakloop(pcap);
}
/******************************************************************************/
pcap_t *
reader_libpcap_open_live(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
    pcap_t *p;
    int status;

    p = pcap_create(source, errbuf);
    if (p == NULL)
        return (NULL);
    status = pcap_set_snaplen(p, snaplen);
    if (status < 0)
        goto fail;
    status = pcap_set_promisc(p, promisc);
    if (status < 0)
        goto fail;
    status = pcap_set_timeout(p, to_ms);
    if (status < 0)
        goto fail;
    status = pcap_set_buffer_size(p, config.pcapBufferSize);
    if (status < 0)
        goto fail;
    status = pcap_activate(p);
    if (status < 0)
        goto fail;
    status = pcap_setnonblock(p, TRUE, errbuf);
    if (status < 0) {
        pcap_close(p);
        return (NULL);
    }

    return (p);
fail:
    if (status == PCAP_ERROR)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", source,
            pcap_geterr(p));
    else if (status == PCAP_ERROR_NO_SUCH_DEVICE ||
        status == PCAP_ERROR_PERM_DENIED)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s (%s)", source,
            pcap_statustostr(status), pcap_geterr(p));
    else
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", source,
            pcap_statustostr(status));
    pcap_close(p);
    return (NULL);
}
/******************************************************************************/
int reader_libpcap_should_filter(const MolochPacket_t *packet)
{
    if (bpf_programs) {
        int i;
        for (i = 0; i < config.dontSaveBPFsNum; i++) {
            if (bpf_filter(bpf_programs[i].bf_insns, packet->pkt, packet->pktlen, packet->pktlen)) {
                return i;
                break;
            }
        }
    }
    return -1;
}
/******************************************************************************/
void reader_libpcap_init(char *UNUSED(name))
{
    char errbuf[1024];

#ifdef SNF
    pcap = pcap_open_live(config.interface, 16384, 1, 0, errbuf);
#else
    pcap = reader_libpcap_open_live(config.interface, 16384, 1, 0, errbuf);
#endif

    if (!pcap) {
        LOG("pcap open live failed! %s", errbuf);
        exit(1);
    }

    pcap_setnonblock(pcap, FALSE, errbuf);

    moloch_reader_start         = reader_libpcap_start;
    moloch_reader_stop          = reader_libpcap_stop;
    moloch_reader_stats         = reader_libpcap_stats;
    moloch_reader_should_filter = reader_libpcap_should_filter;
}
