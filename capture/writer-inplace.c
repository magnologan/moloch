/******************************************************************************/
/* writer-inplace.c  -- Writer that doesn't actually write pcap instead using
 *                      location of reading
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
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>

extern MolochConfig_t        config;


static char                 *outputFileName;
static uint32_t              outputId;
static FILE                 *inputFile;
static char                  inputFilename[PATH_MAX+1];

typedef struct moloch_output {
    char      *buf;
    uint64_t   max;
    uint64_t   pos;
    int        ref;
} MolochInplaceOutput_t;

LOCAL MolochInplaceOutput_t *current;
LOCAL MOLOCH_LOCK_DEFINE(current);

/******************************************************************************/
uint32_t writer_inplace_queue_length()
{
    return 0;
}
/******************************************************************************/
void writer_inplace_flush(gboolean UNUSED(all))
{
}
/******************************************************************************/
void writer_inplace_exit()
{
}
/******************************************************************************/
void writer_inplace_create(MolochPacket_t * const packet, char *filename)
{
    if (config.dryRun) {
        outputFileName = "dryrun.pcap";
        return;
    }

    struct stat st;

    fstat(fileno(inputFile), &st);

    outputFileName = moloch_db_create_file(packet->ts.tv_sec, filename, st.st_size, 1, &outputId);
}

/******************************************************************************/
void
writer_inplace_write(MolochPacket_t * const packet)
{
    MOLOCH_LOCK(current);
    if (!current) {
        current = MOLOCH_TYPE_ALLOC0(MolochInplaceOutput_t);
        current->max = config.pcapWriteSize;
        current->buf = mmap (0, config.pcapWriteSize + 20000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    }

    memcpy(current->buf + current->pos, packet->pkt, packet->pktlen);
    packet->pkt = (uint8_t *)current->buf + current->pos;
    current->pos += packet->pktlen;
    current->ref++;
    packet->writerData = current;

    if(current->pos > current->max) {
        current = NULL;
    }
    MOLOCH_UNLOCK(current);

    if (!outputFileName)
        writer_inplace_create(packet, inputFilename);

    packet->writerFileNum = outputId;
    packet->writerFilePos = packet->readerFilePos;
}
/******************************************************************************/
void
writer_inplace_finish(MolochPacket_t * const packet)
{

    MolochInplaceOutput_t *output = packet->writerData;

    MOLOCH_LOCK(current);
    output->ref--;
    if (output->ref == 0 && output != current) {
        MOLOCH_TYPE_FREE(MolochInplaceOutput_t, output);
    }
    MOLOCH_UNLOCK(current);
}
/******************************************************************************/
char *
writer_inplace_name() {
    return inputFilename;
}
/******************************************************************************/
void
writer_inplace_next_input(FILE *file, char *filename) {
    inputFile = file;
    strcpy(inputFilename, filename);
    if (!config.dryRun) {
        g_free(outputFileName);
    }
    outputFileName = 0;
}
/******************************************************************************/
void writer_inplace_init(char *UNUSED(name))
{
    moloch_writer_queue_length = writer_inplace_queue_length;
    moloch_writer_flush        = writer_inplace_flush;
    moloch_writer_exit         = writer_inplace_exit;
    moloch_writer_write        = writer_inplace_write;
    moloch_writer_finish       = writer_inplace_finish;
    moloch_writer_next_input   = writer_inplace_next_input;
    moloch_writer_name         = writer_inplace_name;
}
