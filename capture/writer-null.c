/******************************************************************************/
/* writer-null.c  -- writer that doesn't do anything
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

static uint32_t              outputFilePos = 24;

typedef struct moloch_output {
    char      *buf;
    uint64_t   max;
    uint64_t   pos;
    int        ref;
} MolochNullOutput_t;

LOCAL MolochNullOutput_t *current;
LOCAL MOLOCH_LOCK_DEFINE(current);


/******************************************************************************/
uint32_t writer_null_queue_length()
{
    return 0;
}
/******************************************************************************/
void moloch_writer_null_flush(gboolean UNUSED(all))
{
}
/******************************************************************************/
void writer_null_exit()
{
}
/******************************************************************************/
void
moloch_writer_null_write(MolochPacket_t * const packet)
{
    MOLOCH_LOCK(current);
    if (!current) {
        current = MOLOCH_TYPE_ALLOC0(MolochNullOutput_t);
        current->max = config.pcapWriteSize;
        current->buf = mmap (0, config.pcapWriteSize + 20000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    }

    memcpy(current->buf + current->pos, packet->pkt, packet->pktlen);
    current->pos += packet->pktlen;
    current->ref++;
    packet->pkt = (uint8_t *)current->buf + current->pos;
    packet->writerData = current;

    if(current->pos > current->max) {
        current = NULL;
    }
    MOLOCH_UNLOCK(current);


    packet->writerFileNum = 0;
    packet->writerFilePos = outputFilePos;
    outputFilePos += 16 + packet->pktlen;
}
/******************************************************************************/
void
moloch_writer_null_finish(MolochPacket_t * const packet)
{
    MolochNullOutput_t *output = packet->writerData;

    MOLOCH_LOCK(current);
    output->ref--;
    if (output->ref == 0 && output != current) {
        MOLOCH_TYPE_FREE(MolochNullOutput_t, output);
    }
    MOLOCH_UNLOCK(current);
}
/******************************************************************************/
char *
writer_null_name() {
    return "null";
}
/******************************************************************************/
void writer_null_init(char *UNUSED(name))
{
    moloch_writer_queue_length = writer_null_queue_length;
    moloch_writer_flush        = moloch_writer_null_flush;
    moloch_writer_exit         = writer_null_exit;
    moloch_writer_write        = moloch_writer_null_write;
    moloch_writer_finish       = moloch_writer_null_finish;
    moloch_writer_name         = writer_null_name;
}
