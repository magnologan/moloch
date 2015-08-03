/* session.c  -- Session functions
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "moloch.h"

/******************************************************************************/
extern MolochConfig_t        config;
extern uint32_t              pluginsCbs;
extern time_t                lastPacketSecs;

/******************************************************************************/

static int                   tagsField;
static int                   protocolField;

static MolochSessionHead_t   closingQ;
MolochSessionHead_t          tcpWriteQ;
MOLOCH_LOCK_DEFINE(tcpWriteQ);

typedef HASHP_VAR(h_, MolochSessionHash_t, MolochSessionHead_t);

static MolochSessionHead_t   sessionsQ[SESSION_MAX];
static MolochSessionHash_t   sessions[SESSION_MAX];
static MOLOCH_LOCK_DEFINE(sessions);

/******************************************************************************/
void moloch_session_id (char *buf, uint32_t addr1, uint16_t port1, uint32_t addr2, uint16_t port2)
{
    if (addr1 < addr2) {
        *(uint32_t *)buf = addr1;
        *(uint16_t *)(buf+4) = port1;
        *(uint32_t *)(buf+6) = addr2;
        *(uint16_t *)(buf+10) = port2;
    } else if (addr1 > addr2) {
        *(uint32_t *)buf = addr2;
        *(uint16_t *)(buf+4) = port2;
        *(uint32_t *)(buf+6) = addr1;
        *(uint16_t *)(buf+10) = port1;
    } else if (ntohs(port1) < ntohs(port2)) {
        *(uint32_t *)buf = addr1;
        *(uint16_t *)(buf+4) = port1;
        *(uint32_t *)(buf+6) = addr2;
        *(uint16_t *)(buf+10) = port2;
    } else {
        *(uint32_t *)buf = addr2;
        *(uint16_t *)(buf+4) = port2;
        *(uint32_t *)(buf+6) = addr1;
        *(uint16_t *)(buf+10) = port1;
    }
}
/******************************************************************************/
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#define int_ntoa(x)     inet_ntoa(*((struct in_addr *)(int*)&x))

char *moloch_session_id_string (int protocol, uint32_t addr1, int port1, uint32_t addr2, int port2)
{
    static char buf[1000];
    int         len;

    if (addr1 < addr2) {
        len = snprintf(buf, sizeof(buf), "%d;%s:%i,", protocol, int_ntoa(addr1), port1);
        snprintf(buf+len, sizeof(buf) - len, "%s:%i", int_ntoa(addr2), port2);
    } else if (addr1 > addr2) {
        len = snprintf(buf, sizeof(buf), "%d;%s:%i,", protocol, int_ntoa(addr2), port2);
        snprintf(buf+len, sizeof(buf) - len, "%s:%i", int_ntoa(addr1), port1);
    } else if (port1 < port2) {
        len = snprintf(buf, sizeof(buf), "%d;%s:%i,", protocol, int_ntoa(addr1), port1);
        snprintf(buf+len, sizeof(buf) - len, "%s:%i", int_ntoa(addr2), port2);
    } else {
        len = snprintf(buf, sizeof(buf), "%d;%s:%i,", protocol, int_ntoa(addr2), port2);
        snprintf(buf+len, sizeof(buf) - len, "%s:%i", int_ntoa(addr1), port1);
    }

    return buf;
}
/******************************************************************************/
/* Must match moloch_session_cmp and moloch_session_id
 * a1 0-3
 * p1 4-5
 * a2 6-9
 * p2 10-11
 */
uint32_t moloch_session_hash(const void *key)
{
    unsigned char *p = (unsigned char *)key;
    //return ((p[2] << 16 | p[3] << 8 | p[4]) * 59) ^ (p[8] << 16 | p[9] << 8 |  p[10]);
    return (((p[1]<<24) ^ (p[2]<<18) ^ (p[3]<<12) ^ (p[4]<<6) ^ p[5]) * 13) ^ (p[8]<<24|p[9]<<16 | p[10]<<8 | p[11]);
}

/******************************************************************************/
int moloch_session_cmp(const void *keyv, const void *elementv)
{
    MolochSession_t *session = (MolochSession_t *)elementv;

    return (*(uint64_t *)keyv     == session->sessionIda && 
            *(uint32_t *)(keyv+8) == session->sessionIdb);
}
/******************************************************************************/
void moloch_session_get_tag_cb(void *sessionV, int tagType, const char *tagName, uint32_t tag, gboolean async)
{
    MolochSession_t *session = sessionV;

    if (async)
        MOLOCH_LOCK(session->lock);

    if (tag == 0) {
        LOG("ERROR - Not adding tag %s type %d couldn't get tag num", tagName, tagType);
    } else {
        moloch_field_int_add(tagType, session, tag);
    }

    if (moloch_session_decr_outstanding(session) && async)
        MOLOCH_UNLOCK(session->lock);
}
/******************************************************************************/
gboolean moloch_session_has_tag(MolochSession_t *session, const char *tagName)
{
    uint32_t tagValue;

    if (!session->fields[tagsField])
        return FALSE;

    if ((tagValue = moloch_db_peek_tag(tagName)) == 0)
        return FALSE;

    MolochInt_t          *hint;
    HASH_FIND_INT(i_, *(session->fields[tagsField]->ihash), tagValue, hint);
    return hint != 0;
}
/******************************************************************************/
void moloch_session_add_protocol(MolochSession_t *session, const char *protocol)
{
    moloch_field_string_add(protocolField, session, protocol, -1, TRUE);
}
/******************************************************************************/
gboolean moloch_session_has_protocol(MolochSession_t *session, const char *protocol)
{
    if (!session->fields[protocolField])
        return FALSE;

    MolochString_t          *hstring;
    HASH_FIND(s_, *(session->fields[protocolField]->shash), protocol, hstring);
    return hstring != 0;
}
/******************************************************************************/
void moloch_session_add_tag(MolochSession_t *session, const char *tag) {
    moloch_session_incr_outstanding(session);
    moloch_db_get_tag(session, tagsField, tag, moloch_session_get_tag_cb);

    if (session->stopSaving == 0 && HASH_COUNT(s_, config.dontSaveTags)) {
        MolochString_t *tstring;

        HASH_FIND(s_, config.dontSaveTags, tag, tstring);
        if (tstring) {
            session->stopSaving = (int)(long)tstring->uw;
        }
    }
}

/******************************************************************************/
void moloch_session_add_tag_type(MolochSession_t *session, int tagtype, const char *tag) {
    moloch_session_incr_outstanding(session);
    moloch_db_get_tag(session, tagtype, tag, moloch_session_get_tag_cb);

    if (session->stopSaving == 0 && HASH_COUNT(s_, config.dontSaveTags)) {
        MolochString_t *tstring;

        HASH_FIND(s_, config.dontSaveTags, tag, tstring);
        if (tstring) {
            session->stopSaving = (long)tstring->uw;
        }
    }
}
/******************************************************************************/
// session should already be locked
void moloch_session_mark_for_close (MolochSession_t *session, int ses)
{
    session->closingQ = 1;
    session->saveTime = session->lastPacket.tv_sec + 5;
    MOLOCH_LOCK(sessions);
    DLL_REMOVE(q_, &sessionsQ[ses], session);
    DLL_PUSH_TAIL(q_, &closingQ, session);
    MOLOCH_UNLOCK(sessions);

    if (session->tcp_next) {
        MOLOCH_LOCK(tcpWriteQ);
        DLL_REMOVE(tcp_, &tcpWriteQ, session);
        MOLOCH_UNLOCK(tcpWriteQ);
    }
}
/******************************************************************************/
void moloch_session_free (MolochSession_t *session)
{
    if (session->tcp_next) {
        MOLOCH_LOCK(tcpWriteQ);
        DLL_REMOVE(tcp_, &tcpWriteQ, session);
        MOLOCH_UNLOCK(tcpWriteQ);
    }

    g_array_free(session->filePosArray, TRUE);
    g_array_free(session->fileLenArray, TRUE);
    g_array_free(session->fileNumArray, TRUE);

    if (session->rootId)
        g_free(session->rootId);

    if (session->parserInfo) {
        int i;
        for (i = 0; i < session->parserNum; i++) {
            if (session->parserInfo[i].parserFreeFunc)
                session->parserInfo[i].parserFreeFunc(session, session->parserInfo[i].uw);
        }
        free(session->parserInfo);
    }

    if (session->pluginData)
        MOLOCH_SIZE_FREE(pluginData, session->pluginData);
    moloch_field_free(session);

    moloch_packet_tcp_free(session);

    MOLOCH_LOCK_FREE(session->lock);
    MOLOCH_TYPE_FREE(MolochSession_t, session);
}
/******************************************************************************/
// session should already be locked
LOCAL void moloch_session_save(MolochSession_t *session)
{
    moloch_packet_tcp_free(session);

    if (session->parserInfo) {
        int i;
        for (i = 0; i < session->parserNum; i++) {
            if (session->parserInfo[i].parserSaveFunc)
                session->parserInfo[i].parserSaveFunc(session, session->parserInfo[i].uw, TRUE);
        }
    }

    if (pluginsCbs & MOLOCH_PLUGIN_PRE_SAVE)
        moloch_plugins_cb_pre_save(session, TRUE);

    if (session->tcp_next) {
        MOLOCH_LOCK(tcpWriteQ);
        DLL_REMOVE(tcp_, &tcpWriteQ, session);
        MOLOCH_UNLOCK(tcpWriteQ);
    }

    if (session->outstandingQueries > 0) {
        session->needSave = 1;

        MOLOCH_SESSION_UNLOCK; // didn't actually free, but should be removed from all globals, unlock ourselves
        return;
    }

    moloch_db_save_session(session, TRUE);
    moloch_session_free(session);
}
/******************************************************************************/
// session should already be locked
void moloch_session_mid_save(MolochSession_t *session, uint32_t tv_sec)
{
    if (session->parserInfo) {
        int i;
        for (i = 0; i < session->parserNum; i++) {
            if (session->parserInfo[i].parserSaveFunc)
                session->parserInfo[i].parserSaveFunc(session, session->parserInfo[i].uw, FALSE);
        }
    }

    if (pluginsCbs & MOLOCH_PLUGIN_PRE_SAVE)
        moloch_plugins_cb_pre_save(session, FALSE);

    /* If we are parsing pcap its ok to pause and make sure all tags are loaded */
    while (session->outstandingQueries > 0 && config.pcapReadOffline) {
        g_main_context_iteration (g_main_context_default(), TRUE);
    }

    if (!session->rootId) {
        session->rootId = "ROOT";
    }

    moloch_db_save_session(session, FALSE);
    g_array_set_size(session->filePosArray, 0);
    g_array_set_size(session->fileLenArray, 0);
    g_array_set_size(session->fileNumArray, 0);
    session->lastFileNum = 0;

    if (session->tcp_next) {
        MOLOCH_LOCK(tcpWriteQ);
        DLL_MOVE_TAIL(tcp_, &tcpWriteQ, session);
        MOLOCH_UNLOCK(tcpWriteQ);
    }

    session->saveTime = tv_sec + config.tcpSaveTimeout;
    session->bytes[0] = 0;
    session->bytes[1] = 0;
    session->databytes[0] = 0;
    session->databytes[1] = 0;
    session->packets[0] = 0;
    session->packets[1] = 0;
}
/******************************************************************************/
// session should already be locked
gboolean moloch_session_decr_outstanding(MolochSession_t *session)
{
    session->outstandingQueries--;
    if (session->needSave && session->outstandingQueries == 0) {
        session->needSave = 0; /* Stop endless loop if plugins add tags */
        moloch_db_save_session(session, TRUE);
        moloch_session_free(session);
        return FALSE;
    }

    return TRUE;
}
/******************************************************************************/
int moloch_session_close_outstanding()
{
    return DLL_COUNT(q_, &closingQ);
}
/******************************************************************************/
// Should only be used by packet, lots of side effects, bad dev
// Returns locked session
MolochSession_t *moloch_session_find_or_create(int ses, char *sessionId, int *isNew)
{
    MolochSession_t *session;

    uint32_t hash = HASH_HASH(sessions[ses], sessionId);

    MOLOCH_LOCK(sessions);
    HASH_FIND_HASH(h_, sessions[ses], hash, sessionId, session);

    if (session) {
        MOLOCH_SESSION_LOCK;
        if (!session->closingQ) {
            DLL_MOVE_TAIL(q_, &sessionsQ[ses], session);
        }
        MOLOCH_UNLOCK(sessions);
        *isNew = 0;
        return session;
    }
    *isNew = 1;

    session = MOLOCH_TYPE_ALLOC0(MolochSession_t);

    memcpy(&session->sessionIda, sessionId, 8);
    memcpy(&session->sessionIdb, sessionId+8, 4);
    MOLOCH_LOCK_INIT(session->lock);

    HASH_ADD_HASH(h_, sessions[ses], hash, sessionId, session);
    DLL_PUSH_TAIL(q_, &sessionsQ[ses], session);
    MOLOCH_UNLOCK(sessions);
    MOLOCH_SESSION_LOCK;

    session->filePosArray = g_array_sized_new(FALSE, FALSE, sizeof(uint64_t), 100);
    session->fileLenArray = g_array_sized_new(FALSE, FALSE, sizeof(uint16_t), 100);
    session->fileNumArray = g_array_new(FALSE, FALSE, 4);
    session->fields = MOLOCH_SIZE_ALLOC0(fields, sizeof(MolochField_t *)*config.maxField);
    session->maxFields = config.maxField;
    DLL_INIT(td_, &session->tcpData);
    if (config.numPlugins > 0)
        session->pluginData = MOLOCH_SIZE_ALLOC0(pluginData, sizeof(void *)*config.numPlugins);

    return session;
}
/******************************************************************************/
uint32_t moloch_session_monitoring()
{
    return HASH_COUNT(h_, sessions[SESSION_TCP]) + HASH_COUNT(h_, sessions[SESSION_UDP]) + HASH_COUNT(h_, sessions[SESSION_ICMP]);
}
/******************************************************************************/
gboolean moloch_session_cleanup_gfunc( gpointer UNUSED(user_data))
{
    int ses;
    MolochSession_t *session;

// Sessions Idle Long Time
    MOLOCH_LOCK(sessions);
    for (ses = 0; ses < SESSION_MAX; ses++) {
        while (1) {
            session = DLL_PEEK_HEAD(q_, &sessionsQ[ses]);
            if (session && (DLL_COUNT(q_, &sessionsQ[ses]) > config.maxStreams ||
                            ((uint64_t)session->lastPacket.tv_sec + config.timeouts[ses] < (uint64_t)lastPacketSecs))) {
                if (session->tfq_next) {
                    LOG("ALW - NOT SAVING BECAUSE TFQ");
                    continue;
                }
                MOLOCH_SESSION_LOCK;
                DLL_REMOVE(q_, &sessionsQ[ses], session);
                if (session->h_next)
                    HASH_REMOVE(h_, sessions[ses], session);
                MOLOCH_UNLOCK(sessions); // Unlock during save
                moloch_session_save(session);
                // session is gone, no need to unlock
                MOLOCH_LOCK(sessions); // Relock for the loop
            } else {
                break;
            }
        }
    }
    MOLOCH_UNLOCK(sessions);


// TCP Sessions Open Long Time
    while (1) {
        MOLOCH_LOCK(tcpWriteQ);
        session = DLL_PEEK_HEAD(tcp_, &tcpWriteQ);
        MOLOCH_UNLOCK(tcpWriteQ);

        if (session && (uint64_t)session->saveTime < (uint64_t)lastPacketSecs) {
            MOLOCH_SESSION_LOCK;
            moloch_session_mid_save(session, session->lastPacket.tv_sec);
            MOLOCH_SESSION_UNLOCK;
        } else {
            break;
        }
    }


// TCP Session Closing Q
    while (1) {
        MOLOCH_LOCK(sessions);
        session = DLL_PEEK_HEAD(q_, &closingQ);
        MOLOCH_UNLOCK(sessions);

        if (session && session->saveTime < (uint64_t)lastPacketSecs) {
            MOLOCH_LOCK(sessions);
            MOLOCH_SESSION_LOCK;
            DLL_REMOVE(q_, &closingQ, session);
            if (session->h_next) {
                HASH_REMOVE(h_, sessions[SESSION_TCP], session);
            }
            MOLOCH_UNLOCK(sessions);
            moloch_session_save(session);
            // session is gone, no need to unlock
        } else {
            break;
        }
    }


// Call again
    return G_SOURCE_CONTINUE;
}


/******************************************************************************/
int moloch_session_watch_count(int ses)
{
    return DLL_COUNT(q_, &sessionsQ[ses]);
}

/******************************************************************************/
int moloch_session_idle_seconds(int ses)
{
    MolochSession_t *session = DLL_PEEK_HEAD(q_, &sessionsQ[ses]);
    return (session?(int)(lastPacketSecs - (session->lastPacket.tv_sec + config.timeouts[ses])):0);
}


/******************************************************************************/
void moloch_session_init()
{
    uint32_t primes[] = {10007, 49999, 99991, 199799, 400009, 500009, 732209, 1092757, 1299827, 1500007, 1987411, 2999999};

    int p;
    for (p = 0; p < 12; p++) {
        if (primes[p] >= config.maxStreams/2)
            break;
    }
    if (p == 12) p = 11;

    tagsField = moloch_field_by_db("ta");

    protocolField = moloch_field_define("general", "termfield",
        "protocols", "Protocols", "prot-term",
        "Protocols set for session",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT | MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
        NULL);

    if (config.debug)
        LOG("session hash size %d", primes[p]);

    HASHP_INIT(h_, sessions[SESSION_UDP], primes[p], moloch_session_hash, moloch_session_cmp);
    HASHP_INIT(h_, sessions[SESSION_TCP], primes[p], moloch_session_hash, moloch_session_cmp);
    HASHP_INIT(h_, sessions[SESSION_ICMP], primes[p], moloch_session_hash, moloch_session_cmp);
    DLL_INIT(tcp_, &tcpWriteQ);
    DLL_INIT(q_, &closingQ);
    DLL_INIT(q_, &sessionsQ[SESSION_UDP]);
    DLL_INIT(q_, &sessionsQ[SESSION_TCP]);
    DLL_INIT(q_, &sessionsQ[SESSION_ICMP]);

    g_timeout_add(1, moloch_session_cleanup_gfunc, NULL);
}
/******************************************************************************/
void moloch_session_flush()
{
    MolochSession_t *session;

    int i;
    for (i = 0; i < SESSION_MAX; i++) {

#ifdef PRINT_BUCKETS
        // Print out the histogram for buckets, see how we are doing
        printf("\nBuckets for %d:\n", i);
        int buckets[51];
        int total[51];
        memset(buckets, 0, sizeof(buckets));
        memset(total, 0, sizeof(total));
        int b;
        for ( b = 0;  b < sessions[i].size;  b++) {
            if (sessions[i].buckets[b].h_count >= 50) {
                buckets[50]++;
                total[50] += sessions[i].buckets[b].h_count;
            } else {
                buckets[(sessions[i].buckets[b].h_count)]++;
                total[(sessions[i].buckets[b].h_count)] += sessions[i].buckets[b].h_count;
            }
        }
        for ( b = 0;  b <= 50;  b++) {
            if (buckets[b])
                printf(" %2d: %7d %7d\n", b, buckets[b], total[b]);
        }
#endif

        MOLOCH_LOCK(sessions);
        HASH_FORALL_POP_HEAD(h_, sessions[i], session,
            if (session->closingQ)
                DLL_REMOVE(q_, &closingQ, session);
            else
                DLL_REMOVE(q_, &sessionsQ[i], session);
            MOLOCH_UNLOCK(sessions);
            MOLOCH_SESSION_LOCK;
            moloch_session_save(session);
            MOLOCH_LOCK(sessions);
        );
        MOLOCH_UNLOCK(sessions);
    }
}
/******************************************************************************/
void moloch_session_exit()
{
    config.exiting = 1;
    LOG("sessions: %d tcp: %d udp: %d icmp: %d",
            moloch_session_monitoring(),
            sessionsQ[SESSION_TCP].q_count,
            sessionsQ[SESSION_UDP].q_count,
            sessionsQ[SESSION_ICMP].q_count);

    moloch_session_flush();

    if (!config.dryRun && config.copyPcap) {
        moloch_writer_exit();
    }
}
