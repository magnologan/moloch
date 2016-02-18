/* Copyright 2012-2016 AOL Inc. All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "moloch.h"

typedef struct {
    uint32_t   sshLen;
} SSHInfo_t;

static int verField;
static int keyField;

/******************************************************************************/
// SSH Parsing currently assumes the parts we want from a SSH Packet will be
// in a single TCP packet.  Kind of sucks.
int ssh_parser(MolochSession_t *session, void *uw, const unsigned char *data, int remaining, int which)
{
    SSHInfo_t *ssh = uw;

    if (memcmp("SSH", data, 3) == 0) {
        unsigned char *n = memchr(data, 0x0a, remaining);
        if (n && *(n-1) == 0x0d)
            n--;

        if (n) {
            int len = (n - data);

            char *str = g_ascii_strdown((char *)data, len);

            if (!moloch_field_string_add(verField, session, str, len, FALSE)) {
                g_free(str);
            }
        }
        return 0;
    }

    if (which != 1)
        return 0;

    BSB bsb;
    BSB_INIT(bsb, data, remaining);

    while (BSB_REMAINING(bsb) > 6) {
        uint32_t loopRemaining = BSB_REMAINING(bsb);

        // If 0 looking for a ssh packet, otherwise in the middle of ssh packet
        if (ssh->sshLen == 0) {
            BSB_IMPORT_u32(bsb, ssh->sshLen);

            // Can't have a ssh packet > 35000 bytes.
            if (ssh->sshLen >= 35000) {
                moloch_parsers_unregister(session, uw);
                return 0;
            }
            ssh->sshLen += 4;

            uint8_t    sshCode = 0;
            BSB_IMPORT_skip(bsb, 1); // padding length
            BSB_IMPORT_u08(bsb, sshCode);

            if (sshCode == 33) {
                moloch_parsers_unregister(session, uw);

                uint32_t keyLen = 0;
                BSB_IMPORT_u32(bsb, keyLen);

                if (!BSB_IS_ERROR(bsb) && BSB_REMAINING(bsb) >= keyLen) {
                    char *str = g_base64_encode(BSB_WORK_PTR(bsb), keyLen);
                    if (!moloch_field_string_add(keyField, session, str, (keyLen/3+1)*4, FALSE)) {
                        g_free(str);
                    }
                }
                break;
            }
        }

        if (loopRemaining > ssh->sshLen) {
            // Processed all, looking for another packet
            BSB_IMPORT_skip(bsb, loopRemaining);
            ssh->sshLen = 0;
            continue;
        } else {
            // Waiting on more data then in this callback
            ssh->sshLen -= loopRemaining;
            break;
        }
    }
    return 0;
}
/******************************************************************************/
void ssh_free(MolochSession_t UNUSED(*session), void *uw)
{
    SSHInfo_t            *ssh          = uw;

    MOLOCH_TYPE_FREE(SSHInfo_t, ssh);
}
/******************************************************************************/
void ssh_classify(MolochSession_t *session, const unsigned char *UNUSED(data), int UNUSED(len), int which)
{
    if (moloch_nids_has_protocol(session, "ssh"))
        return;

    moloch_session_add_protocol(session, "ssh");

    SSHInfo_t            *ssh          = MOLOCH_TYPE_ALLOC0(SSHInfo_t);

    moloch_parsers_register(session, ssh_parser, ssh, ssh_free);
    ssh_parser(session, ssh, data, len, which);
}
/******************************************************************************/
void moloch_parser_init()
{
    verField = moloch_field_define("ssh", "lotermfield",
        "ssh.ver", "Version", "sshver",
        "SSH Software Version",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    keyField = moloch_field_define("ssh", "termfield",
        "ssh.key", "Key", "sshkey",
        "SSH Key",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    moloch_parsers_classifier_register_tcp("ssh", 0, (unsigned char*)"SSH", 3, ssh_classify);
}

