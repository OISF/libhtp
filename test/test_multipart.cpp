/***************************************************************************
 * Copyright (c) 2009-2010 Open Information Security Foundation
 * Copyright (c) 2010-2013 Qualys, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.

 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.

 * - Neither the name of the Qualys, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***************************************************************************/

/**
 * @file
 * @author Ivan Ristic <ivanr@webkreator.com>
 */

#include <iostream>
#include <gtest/gtest.h>
#include <htp/htp_private.h>
#include "test.h"

//#include <htp/htp_multipart.h>

class Multipart : public testing::Test {
protected:

    void parseRequest(char *headers[], char *data[]) {
        size_t i;

        // Calculate body length.
        size_t bodyLen = 0;
        for (i = 0; data[i] != NULL; i++) {
            bodyLen += strlen(data[i]);
        }

        // Open connection
        connp = htp_connp_create(cfg);
        htp_connp_open(connp, "127.0.0.1", 32768, "127.0.0.1", 80, NULL);

        // Send headers.

        for (i = 0; headers[i] != NULL; i++) {
            htp_connp_req_data(connp, NULL, headers[i], strlen(headers[i]));
        }

        char buf[32];
        snprintf(buf, sizeof (buf), "Content-Length: %ld\r\n", bodyLen);
        htp_connp_req_data(connp, NULL, buf, strlen(buf));

        htp_connp_req_data(connp, NULL, (void *) "\r\n", 2);

        // Send data.
        for (i = 0; data[i] != NULL; i++) {
            htp_connp_req_data(connp, NULL, data[i], strlen(data[i]));
        }

        ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

        tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
        ASSERT_TRUE(tx != NULL);

        //ASSERT_TRUE(tx->request_mpartp != NULL);
        //mpartp = tx->request_mpartp;
        //body = htp_mpartp_get_multipart(mpartp);
        //ASSERT_TRUE(body != NULL);
    }

    void parseRequestThenVerify(char *headers[], char *data[]) {
        parseRequest(headers, data);

        /*
        ASSERT_TRUE(body != NULL);
        ASSERT_TRUE(body->parts != NULL);
        ASSERT_TRUE(htp_list_size(body->parts) == 3);

        ASSERT_FALSE(body->flags & HTP_MULTIPART_INCOMPLETE);

        // Field 1
        htp_multipart_part_t *field1 = (htp_multipart_part_t *) htp_list_get(body->parts, 0);
        ASSERT_TRUE(field1 != NULL);
        ASSERT_EQ(MULTIPART_PART_TEXT, field1->type);
        ASSERT_TRUE(field1->name != NULL);
        ASSERT_TRUE(bstr_cmp_c(field1->name, "field1") == 0);
        ASSERT_TRUE(field1->value != NULL);
        ASSERT_TRUE(bstr_cmp_c(field1->value, "ABCDEF") == 0);

        // File 1
        htp_multipart_part_t *file1 = (htp_multipart_part_t *) htp_list_get(body->parts, 1);
        ASSERT_TRUE(file1 != NULL);
        ASSERT_EQ(MULTIPART_PART_FILE, file1->type);
        ASSERT_TRUE(file1->name != NULL);
        ASSERT_TRUE(bstr_cmp_c(file1->name, "file1") == 0);
        ASSERT_TRUE(file1->filename != NULL);
        ASSERT_TRUE(bstr_cmp_c(file1->filename, "file.bin") == 0);

        // Field 2
        htp_multipart_part_t *field2 = (htp_multipart_part_t *) htp_list_get(body->parts, 2);
        ASSERT_TRUE(field2 != NULL);
        ASSERT_EQ(MULTIPART_PART_TEXT, field2->type);
        ASSERT_TRUE(field2->name != NULL);
        ASSERT_TRUE(bstr_cmp_c(field2->name, "field2") == 0);
        ASSERT_TRUE(field2->value != NULL);
        ASSERT_TRUE(bstr_cmp_c(field2->value, "GHIJKL") == 0);
        */
    }

    void parseParts(char *parts[]) {
        mpartp = htp_multipart_create(cfg, bstr_dup_c("0123456789"), 0 /* flags */);

        size_t i = 0;
        for (;;) {
            if (parts[i] == NULL) break;
            htp_multipart_parse(mpartp, parts[i], strlen(parts[i]));
            i++;
        }

        htp_multipart_finalize(mpartp);

        //body = htp_mpartp_get_multipart(mpartp);
        //ASSERT_TRUE(body != NULL);
    }

    void parsePartsThenVerify(char *parts[]) {
        parseParts(parts);

        /*
        // Examine the result
        body = htp_mpartp_get_multipart(mpartp);
        ASSERT_TRUE(body != NULL);

        ASSERT_TRUE(htp_list_size(body->parts) == 2);

        for (size_t i = 0, n = htp_list_size(body->parts); i < n; i++) {
            htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, i);

            switch (i) {
                case 0:
                    ASSERT_EQ(MULTIPART_PART_TEXT, part->type);
                    ASSERT_TRUE(part->name != NULL);
                    ASSERT_TRUE(bstr_cmp_c(part->name, "field1") == 0);
                    ASSERT_TRUE(part->value != NULL);
                    ASSERT_TRUE(bstr_cmp_c(part->value, "ABCDEF") == 0);
                    break;
                case 1:
                    ASSERT_EQ(MULTIPART_PART_TEXT, part->type);
                    ASSERT_TRUE(part->name != NULL);
                    ASSERT_TRUE(bstr_cmp_c(part->name, "field2") == 0);
                    ASSERT_TRUE(part->value != NULL);
                    ASSERT_TRUE(bstr_cmp_c(part->value, "GHIJKL") == 0);
                    break;
            }
        }
        */
    }

    virtual void SetUp() {
        cfg = htp_config_create();
        htp_config_set_server_personality(cfg, HTP_SERVER_APACHE_2);
        htp_config_register_multipart_parser(cfg);

        connp = NULL;
        mpartp = NULL;
        // body = NULL;
        tx = NULL;
    }

    virtual void TearDown() {
        if (connp != NULL) {
            htp_connp_destroy_all(connp);
        } else if (mpartp != NULL) {
            htp_multipart_destroy(mpartp);
        }

        if (cfg != NULL) {
            htp_config_destroy(cfg);
        }
    }

    htp_tx_t *tx;

    htp_connp_t *connp;

    //htp_multipart_t *body;

    htp_multipart_parser_t *mpartp;

    htp_cfg_t *cfg;
};

TEST_F(Multipart, TestX_1) {
    mpartp = htp_multipart_create(cfg, bstr_dup_c("---------------------------41184676334"), 0 /* flags */);

    char *parts[999];

    size_t i = 0;
    parts[i++] = (char *) "-----------------------------41184676334\r\n";
    parts[i++] = (char *) "DATA";
    parts[i++] = (char *) "\r\n-----------------------------41184676334--";
    parts[i++] = NULL;

    i = 0;
    for (;;) {
        if (parts[i] == NULL) break;
        htp_multipart_parse(mpartp, parts[i], strlen(parts[i]));
        i++;
    }

    htp_multipart_finalize(mpartp);
    htp_multipart_destroy(mpartp);
    mpartp = NULL;
}

TEST_F(Multipart, TestX_2) {
    mpartp = htp_multipart_create(cfg, bstr_dup_c("---------------------------41184676334"), 0 /* flags */);

    char *parts[999];

    size_t i = 0;
    parts[i++] = (char *) "\r\n-----------------------------41184676334\r\n";
    parts[i++] = (char *) "DATA";
    parts[i++] = (char *) "\r\n-----------------------------41184676334--";
    parts[i++] = NULL;

    i = 0;
    for (;;) {
        if (parts[i] == NULL) break;
        htp_multipart_parse(mpartp, parts[i], strlen(parts[i]));
        i++;
    }

    htp_multipart_finalize(mpartp);
    htp_multipart_destroy(mpartp);
    mpartp = NULL;
}

TEST_F(Multipart, TestX_3) {
    mpartp = htp_multipart_create(cfg, bstr_dup_c("---------------------------41184676334"), 0 /* flags */);

    char *parts[999];

    size_t i = 0;
    parts[i++] = (char *) "\r\n-----------------------------41184676334\r\n";
    parts[i++] = (char *) "\r\n--DATA";
    parts[i++] = (char *) "\r\n-----------------------------41184676334--";
    parts[i++] = NULL;

    i = 0;
    for (;;) {
        if (parts[i] == NULL) break;
        htp_multipart_parse(mpartp, parts[i], strlen(parts[i]));
        i++;
    }

    htp_multipart_finalize(mpartp);
    htp_multipart_destroy(mpartp);
    mpartp = NULL;
}

TEST_F(Multipart, TestX_4) {
    mpartp = htp_multipart_create(cfg, bstr_dup_c("---------------------------41184676334"), 0 /* flags */);

    char *parts[999];

    size_t i = 0;
    parts[i++] = (char *) "\r\n-----------------------------";
    parts[i++] = (char *) "41184676334\r\n";
    parts[i++] = (char *) "\r\n--DATA";
    parts[i++] = (char *) "\r\n-----------------------------41184676334--";
    parts[i++] = NULL;

    i = 0;
    for (;;) {
        if (parts[i] == NULL) break;
        htp_multipart_parse(mpartp, parts[i], strlen(parts[i]));
        i++;
    }

    htp_multipart_finalize(mpartp);
    htp_multipart_destroy(mpartp);
    mpartp = NULL;
}

TEST_F(Multipart, TestX_5) {
    mpartp = htp_multipart_create(cfg, bstr_dup_c("---------------------------41184676334"), 0 /* flags */);

    char *parts[999];

    size_t i = 0;
    parts[i++] = (char *) "\r\n-----------------------------41184676334\r\n";
    parts[i++] = (char *) "\r\n";
    parts[i++] = (char *) "--DATA";
    parts[i++] = (char *) "\r\n-----------------------------41184676334--";
    parts[i++] = NULL;

    i = 0;
    for (;;) {
        if (parts[i] == NULL) break;
        htp_multipart_parse(mpartp, parts[i], strlen(parts[i]));
        i++;
    }

    htp_multipart_finalize(mpartp);
    htp_multipart_destroy(mpartp);
    mpartp = NULL;
}

TEST_F(Multipart, TestX_6) {
    mpartp = htp_multipart_create(cfg, bstr_dup_c("---------------------------41184676334"), 0 /* flags */);

    char *parts[999];

    size_t i = 0;
    parts[i++] = (char *) "-----------------------------\r\n";
    parts[i++] = (char *) "DATA";
    parts[i++] = (char *) "\r\n-----------------------------41184676334--";
    parts[i++] = NULL;

    i = 0;
    for (;;) {
        if (parts[i] == NULL) break;
        htp_multipart_parse(mpartp, parts[i], strlen(parts[i]));
        i++;
    }

    htp_multipart_finalize(mpartp);
    htp_multipart_destroy(mpartp);
    mpartp = NULL;
}
