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

#include <htp/htp_multipart_private.h>

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
        snprintf(buf, sizeof (buf), "Content-Length: %zu\r\n", bodyLen);
        htp_connp_req_data(connp, NULL, buf, strlen(buf));

        htp_connp_req_data(connp, NULL, (void *) "\r\n", 2);

        // Send data.
        for (i = 0; data[i] != NULL; i++) {
            htp_connp_req_data(connp, NULL, data[i], strlen(data[i]));
        }

        ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

        tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
        ASSERT_TRUE(tx != NULL);

        ASSERT_TRUE(tx->request_mpartp != NULL);
        mpartp = tx->request_mpartp;
        body = htp_mpartp_get_multipart(mpartp);
        ASSERT_TRUE(body != NULL);
    }

    void parseRequestThenVerify(char *headers[], char *data[]) {
        parseRequest(headers, data);

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
        ASSERT_TRUE(file1->file->filename != NULL);
        ASSERT_TRUE(bstr_cmp_c(file1->file->filename, "file.bin") == 0);

        // Field 2
        htp_multipart_part_t *field2 = (htp_multipart_part_t *) htp_list_get(body->parts, 2);
        ASSERT_TRUE(field2 != NULL);
        ASSERT_EQ(MULTIPART_PART_TEXT, field2->type);
        ASSERT_TRUE(field2->name != NULL);
        ASSERT_TRUE(bstr_cmp_c(field2->name, "field2") == 0);
        ASSERT_TRUE(field2->value != NULL);
        ASSERT_TRUE(bstr_cmp_c(field2->value, "GHIJKL") == 0);
    }

    void parseParts(char *parts[]) {
        mpartp = htp_mpartp_create(cfg, bstr_dup_c("0123456789"), 0 /* flags */);

        size_t i = 0;
        for (;;) {
            if (parts[i] == NULL) break;
            htp_mpartp_parse(mpartp, parts[i], strlen(parts[i]));
            i++;
        }

        htp_mpartp_finalize(mpartp);

        body = htp_mpartp_get_multipart(mpartp);
        ASSERT_TRUE(body != NULL);
    }

    void parsePartsThenVerify(char *parts[]) {
        parseParts(parts);

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
    }

    virtual void SetUp() {
        cfg = htp_config_create();
        htp_config_set_server_personality(cfg, HTP_SERVER_APACHE_2);
        htp_config_register_multipart_parser(cfg);

        connp = NULL;
        mpartp = NULL;
        body = NULL;
        tx = NULL;
    }

    virtual void TearDown() {
        if (connp != NULL) {
            htp_connp_destroy_all(connp);
        } else if (mpartp != NULL) {
            htp_mpartp_destroy(mpartp);
        }

        if (cfg != NULL) {
            htp_config_destroy(cfg);
        }
    }

    htp_tx_t *tx;

    htp_connp_t *connp;

    htp_multipart_t *body;

    htp_mpartp_t *mpartp;

    htp_cfg_t *cfg;
};

TEST_F(Multipart, Test1) {
    mpartp = htp_mpartp_create(cfg, bstr_dup_c("---------------------------41184676334"), 0 /* flags */);

    char *parts[999];

    size_t i = 0;
    parts[i++] = (char *) "-----------------------------41184676334\r\n";
    parts[i++] = (char *) "Content-Disposition: form-data;\n name=\"field1\"\r\n";
    parts[i++] = (char *) "\r\n";
    parts[i++] = (char *) "0123456789\r\n-";
    parts[i++] = (char *) "-------------";
    parts[i++] = (char *) "---------------41184676334\r\n";
    parts[i++] = (char *) "Content-Disposition: form-data;\n name=\"field2\"\r\n";
    parts[i++] = (char *) "\r\n";
    parts[i++] = (char *) "0123456789\r\n-";
    parts[i++] = (char *) "-------------";
    parts[i++] = (char *) "--------------X\r\n";
    parts[i++] = (char *) "-----------------------------41184676334\r\n";
    parts[i++] = (char *) "Content-Disposition: form-data;\n";
    parts[i++] = (char *) " ";
    parts[i++] = (char *) "name=\"field3\"\r\n";
    parts[i++] = (char *) "\r\n";
    parts[i++] = (char *) "9876543210\r\n";
    parts[i++] = (char *) "-----------------------------41184676334\r\n";
    parts[i++] = (char *) "Content-Disposition: form-data; name=\"file1\"; filename=\"New Text Document.txt\"\r\nContent-Type: text/plain\r\n\r\n";
    parts[i++] = (char *) "1FFFFFFFFFFFFFFFFFFFFFFFFFFF\r\n";
    parts[i++] = (char *) "2FFFFFFFFFFFFFFFFFFFFFFFFFFE\r";
    parts[i++] = (char *) "3FFFFFFFFFFFFFFFFFFFFFFFFFFF\r\n4FFFFFFFFFFFFFFFFFFFFFFFFF123456789";
    parts[i++] = (char *) "\r\n";
    parts[i++] = (char *) "-----------------------------41184676334\r\n";
    parts[i++] = (char *) "Content-Disposition: form-data; name=\"file2\"; filename=\"New Text Document.txt\"\r\n";
    parts[i++] = (char *) "Content-Type: text/plain\r\n";
    parts[i++] = (char *) "\r\n";
    parts[i++] = (char *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFZ";
    parts[i++] = (char *) "\r\n-----------------------------41184676334--";
    parts[i++] = NULL;

    i = 0;
    for (;;) {
        if (parts[i] == NULL) break;
        htp_mpartp_parse(mpartp, parts[i], strlen(parts[i]));
        i++;
    }

    htp_mpartp_finalize(mpartp);

    // Examine the result
    htp_multipart_t *body = htp_mpartp_get_multipart(mpartp);
    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(5, htp_list_size(body->parts));

    for (size_t i = 0, n = htp_list_size(body->parts); i < n; i++) {
        htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, i);

        switch (i) {
            case 0:
                ASSERT_TRUE(part->name != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->name, "field1") == 0);
                ASSERT_EQ(MULTIPART_PART_TEXT, part->type);
                ASSERT_TRUE(part->value != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->value, "0123456789") == 0);
                break;
            case 1:
                ASSERT_TRUE(part->name != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->name, "field2") == 0);
                ASSERT_EQ(MULTIPART_PART_TEXT, part->type);
                ASSERT_TRUE(bstr_cmp_c(part->value, "0123456789\r\n----------------------------X") == 0);
                break;
            case 2:
                ASSERT_TRUE(part->name != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->name, "field3") == 0);
                ASSERT_EQ(MULTIPART_PART_TEXT, part->type);
                ASSERT_TRUE(part->value != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->value, "9876543210") == 0);
                break;
            case 3:
                ASSERT_TRUE(part->name != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->name, "file1") == 0);
                ASSERT_EQ(MULTIPART_PART_FILE, part->type);
                break;
            case 4:
                ASSERT_TRUE(part->name != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->name, "file2") == 0);
                ASSERT_EQ(MULTIPART_PART_FILE, part->type);
                break;
            default:
                FAIL() << "More parts than expected";
                break;
        }
    }

    ASSERT_FALSE(body->flags & HTP_MULTIPART_PART_INCOMPLETE);

    htp_mpartp_destroy(mpartp);
    mpartp = NULL;
}

TEST_F(Multipart, Test2) {
    mpartp = htp_mpartp_create(cfg, bstr_dup_c("BBB"), 0 /* flags */);

    const char *i1 = "x0000x\n--BBB\n\nx1111x\n--\nx2222x\n--";
    const char *i2 = "BBB\n\nx3333x\n--B";
    const char *i3 = "B\n\nx4444x\n--BB\r";
    const char *i4 = "\n--B";
    const char *i5 = "B";
    const char *i6 = "B\n\nx5555x\r";
    const char *i7 = "\n--x6666x\r";
    const char *i8 = "-";
    const char *i9 = "-";

    htp_mpartp_parse(mpartp, i1, strlen(i1));
    htp_mpartp_parse(mpartp, i2, strlen(i2));
    htp_mpartp_parse(mpartp, i3, strlen(i3));
    htp_mpartp_parse(mpartp, i4, strlen(i4));
    htp_mpartp_parse(mpartp, i5, strlen(i5));
    htp_mpartp_parse(mpartp, i6, strlen(i6));
    htp_mpartp_parse(mpartp, i7, strlen(i7));
    htp_mpartp_parse(mpartp, i8, strlen(i8));
    htp_mpartp_parse(mpartp, i9, strlen(i9));
    htp_mpartp_finalize(mpartp);

    htp_multipart_t *body = htp_mpartp_get_multipart(mpartp);
    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(4, htp_list_size(body->parts));

    for (size_t i = 0, n = htp_list_size(body->parts); i < n; i++) {
        htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, i);

        switch (i) {
            case 0:
                ASSERT_EQ(MULTIPART_PART_PREAMBLE, part->type);

                ASSERT_TRUE(bstr_cmp_c(part->value, "x0000x") == 0);
                break;
            case 1:
                ASSERT_EQ(MULTIPART_PART_UNKNOWN, part->type);
                ASSERT_TRUE(part->value != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->value, "x1111x\n--\nx2222x") == 0);
                break;
            case 2:
                ASSERT_EQ(MULTIPART_PART_UNKNOWN, part->type);
                ASSERT_TRUE(part->value != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->value, "x3333x\n--BB\n\nx4444x\n--BB") == 0);
                break;
            case 3:
                ASSERT_EQ(MULTIPART_PART_UNKNOWN, part->type);
                ASSERT_TRUE(part->value != NULL);
                ASSERT_TRUE(bstr_cmp_c(part->value, "x5555x\r\n--x6666x\r--") == 0);
                break;
            default:
                FAIL();

        }
    }

    ASSERT_TRUE(body->flags & HTP_MULTIPART_INCOMPLETE);

    htp_mpartp_destroy(mpartp);
    mpartp = NULL;
}

TEST_F(Multipart, Test3) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n",
        "--0",
        "1",
        "2",
        "4: Value\r\n",
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);
}

TEST_F(Multipart, BeginsWithoutLine) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);
}

TEST_F(Multipart, BeginsWithCrLf) {
    char *parts[] = {
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);
}

TEST_F(Multipart, BeginsWithLf) {
    char *parts[] = {
        "\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);
}

TEST_F(Multipart, CrLfLineEndings) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_FALSE(body->flags & HTP_MULTIPART_LF_LINE);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_CRLF_LINE);
}

TEST_F(Multipart, LfLineEndings) {
    char *parts[] = {
        "--0123456789\n"
        "Content-Disposition: form-data; name=\"field1\"\n"
        "\n"
        "ABCDEF"
        "\n--0123456789\n"
        "Content-Disposition: form-data; name=\"field2\"\n"
        "\n"
        "GHIJKL"
        "\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_LF_LINE);
    ASSERT_FALSE(body->flags & HTP_MULTIPART_CRLF_LINE);
}

TEST_F(Multipart, CrAndLfLineEndings1) {
    char *parts[] = {
        "--0123456789\n"
        "Content-Disposition: form-data; name=\"field1\"\n"
        "\n"
        "ABCDEF"
        "\r\n--0123456789\n"
        "Content-Disposition: form-data; name=\"field2\"\n"
        "\n"
        "GHIJKL"
        "\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_LF_LINE);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_CRLF_LINE);
}

TEST_F(Multipart, CrAndLfLineEndings2) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\n"
        "\n"
        "ABCDEF"
        "\n--0123456789\n"
        "Content-Disposition: form-data; name=\"field2\"\n"
        "\n"
        "GHIJKL"
        "\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_LF_LINE);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_CRLF_LINE);
}

TEST_F(Multipart, CrAndLfLineEndings3) {
    char *parts[] = {
        "--0123456789\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_LF_LINE);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_CRLF_LINE);
}

TEST_F(Multipart, CrAndLfLineEndings4) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_LF_LINE);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_CRLF_LINE);
}

TEST_F(Multipart, BoundaryInstanceWithLwsAfter) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789 \r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_BBOUNDARY_LWS_AFTER);
}

TEST_F(Multipart, BoundaryInstanceWithNonLwsAfter1) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789 X \r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_BBOUNDARY_NLWS_AFTER);
}

TEST_F(Multipart, BoundaryInstanceWithNonLwsAfter2) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789-\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_BBOUNDARY_NLWS_AFTER);
}

TEST_F(Multipart, BoundaryInstanceWithNonLwsAfter3) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789\r\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_BBOUNDARY_NLWS_AFTER);
}

TEST_F(Multipart, WithPreamble) {
    char *parts[] = {
        "Preamble"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789 X \r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_HAS_PREAMBLE);

    htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, 0);
    ASSERT_TRUE(part != NULL);
    ASSERT_EQ(MULTIPART_PART_PREAMBLE, part->type);
    ASSERT_TRUE(part->value != NULL);
    ASSERT_TRUE(bstr_cmp_c(part->value, "Preamble") == 0);
}

TEST_F(Multipart, WithEpilogue1) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--\r\n"
        "Epilogue",
        NULL
    };

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_HAS_EPILOGUE);

    htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, 2);
    ASSERT_TRUE(part != NULL);
    ASSERT_EQ(MULTIPART_PART_EPILOGUE, part->type);
    ASSERT_TRUE(part->value != NULL);
    ASSERT_TRUE(bstr_cmp_c(part->value, "Epilogue") == 0);

    ASSERT_FALSE(body->flags & HTP_MULTIPART_INCOMPLETE);
    ASSERT_FALSE(body->flags & HTP_MULTIPART_PART_INCOMPLETE);
}

TEST_F(Multipart, WithEpilogue2) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--\r\n"
        "Epi\nlogue",
        NULL
    };

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_HAS_EPILOGUE);

    htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, 2);
    ASSERT_TRUE(part != NULL);
    ASSERT_EQ(MULTIPART_PART_EPILOGUE, part->type);
    ASSERT_TRUE(part->value != NULL);
    ASSERT_TRUE(bstr_cmp_c(part->value, "Epi\nlogue") == 0);

    ASSERT_FALSE(body->flags & HTP_MULTIPART_INCOMPLETE);
    ASSERT_FALSE(body->flags & HTP_MULTIPART_PART_INCOMPLETE);
}

TEST_F(Multipart, WithEpilogue3) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--\r\n"
        "Epi\r",
        "\n--logue",
        NULL
    };

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_HAS_EPILOGUE);

    htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, 2);
    ASSERT_TRUE(part != NULL);
    ASSERT_EQ(MULTIPART_PART_EPILOGUE, part->type);
    ASSERT_TRUE(part->value != NULL);
    ASSERT_TRUE(bstr_cmp_c(part->value, "Epi\r\n--logue") == 0);

    ASSERT_FALSE(body->flags & HTP_MULTIPART_INCOMPLETE);
    ASSERT_FALSE(body->flags & HTP_MULTIPART_PART_INCOMPLETE);
}

TEST_F(Multipart, WithEpilogue4) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--\r\n"
        "Epilogue1"
        "\r\n--0123456789--\r\n"
        "Epilogue2",
        NULL
    };

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(4, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_HAS_EPILOGUE);

    htp_multipart_part_t *ep1 = (htp_multipart_part_t *) htp_list_get(body->parts, 2);
    ASSERT_TRUE(ep1 != NULL);
    ASSERT_EQ(MULTIPART_PART_EPILOGUE, ep1->type);
    ASSERT_TRUE(ep1->value != NULL);
    ASSERT_TRUE(bstr_cmp_c(ep1->value, "Epilogue1") == 0);

    htp_multipart_part_t *ep2 = (htp_multipart_part_t *) htp_list_get(body->parts, 3);
    ASSERT_TRUE(ep2 != NULL);
    ASSERT_EQ(MULTIPART_PART_EPILOGUE, ep2->type);
    ASSERT_TRUE(ep2->value != NULL);
    ASSERT_TRUE(bstr_cmp_c(ep2->value, "Epilogue2") == 0);

    ASSERT_FALSE(body->flags & HTP_MULTIPART_INCOMPLETE);
    ASSERT_FALSE(body->flags & HTP_MULTIPART_PART_INCOMPLETE);
}

TEST_F(Multipart, HasLastBoundary) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(2, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_SEEN_LAST_BOUNDARY);
}

TEST_F(Multipart, DoesNotHaveLastBoundary) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_FALSE(body->flags & HTP_MULTIPART_SEEN_LAST_BOUNDARY);
}

TEST_F(Multipart, PartAfterLastBoundary) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789--\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789",
        NULL
    };

    parsePartsThenVerify(parts);

    ASSERT_TRUE(body->flags & HTP_MULTIPART_SEEN_LAST_BOUNDARY);
}

TEST_F(Multipart, UnknownPart) {
    char *parts[] = {
        "--0123456789\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789--",
        NULL
    };

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(1, htp_list_size(body->parts));

    htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, 0);
    ASSERT_EQ(MULTIPART_PART_UNKNOWN, part->type);
}

TEST_F(Multipart, WithFile) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"; filename=\"test.bin\"\r\n"
        "Content-Type: application/octet-stream \r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(2, htp_list_size(body->parts));

    htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, 1);
    ASSERT_EQ(MULTIPART_PART_FILE, part->type);
    ASSERT_TRUE(part->content_type != NULL);
    ASSERT_TRUE(bstr_cmp_c(part->content_type, "application/octet-stream") == 0);
    ASSERT_TRUE(part->file != NULL);
    ASSERT_TRUE(bstr_cmp_c(part->file->filename, "test.bin") == 0);
    ASSERT_EQ(6, part->file->len);
}

TEST_F(Multipart, WithFileExternallyStored) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"; filename=\"test.bin\"\r\n"
        "Content-Type: application/octet-stream \r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    cfg->extract_request_files = 1;
    cfg->tmpdir = "/tmp";

    parseParts(parts);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(2, htp_list_size(body->parts));

    htp_multipart_part_t *part = (htp_multipart_part_t *) htp_list_get(body->parts, 1);
    ASSERT_EQ(MULTIPART_PART_FILE, part->type);
    ASSERT_TRUE(part->content_type != NULL);
    ASSERT_TRUE(bstr_cmp_c(part->content_type, "application/octet-stream") == 0);
    ASSERT_TRUE(part->file != NULL);
    ASSERT_TRUE(bstr_cmp_c(part->file->filename, "test.bin") == 0);
    ASSERT_EQ(6, part->file->len);

    ASSERT_TRUE(part->file->tmpname != NULL);

    int fd = open(part->file->tmpname, O_RDONLY | O_BINARY);
    ASSERT_TRUE(fd >= 0);

    struct stat statbuf;
    ASSERT_TRUE((fstat(fd, &statbuf) >= 0));
    ASSERT_EQ(6, statbuf.st_size);

    char buf[7];
    ssize_t result = read(fd, buf, 6);
    ASSERT_EQ(6, result);
    buf[6] = '\0';

    ASSERT_STREQ("GHIJKL", buf);

    close(fd);
}

TEST_F(Multipart, PartHeadersEmptyLineBug) {
    char *parts[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r",
        "\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parsePartsThenVerify(parts);
}

TEST_F(Multipart, CompleteRequest) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequestThenVerify(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_FALSE(body->flags & HTP_MULTIPART_PART_HEADER_FOLDING);
}

TEST_F(Multipart, InvalidHeader1) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // Colon missing.

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_INVALID);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidHeader2) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // Whitespace after header name.

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition : form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_INVALID);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidHeader3) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // Whitespace before header name.

    char *data[] = {
        "--0123456789\r\n"
        " Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_INVALID);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidHeader4) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // Invalid header name; contains a space.

    char *data[] = {
        "--0123456789\r\n"
        "Content Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_INVALID);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidHeader5) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // No header name.

    char *data[] = {
        "--0123456789\r\n"
        ": form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_INVALID);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidHeader6) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // No header name.

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: \r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_INVALID);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, NulByte) {
    mpartp = htp_mpartp_create(cfg, bstr_dup_c("0123456789"), 0 /* flags */);

    // NUL byte in the part header.

    char i1[] = "--0123456789\r\n"
            "Content-Disposition: form-data; ";
    char i2[] = "";
    char i3[] =
            "name=\"field1\"\r\n"
            "\r\n"
            "ABCDEF"
            "\r\n--0123456789\r\n"
            "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
            "\r\n"
            "FILEDATA"
            "\r\n--0123456789\r\n"
            "Content-Disposition: form-data; name=\"field2\"\r\n"
            "\r\n"
            "GHIJKL"
            "\r\n--0123456789--";

    htp_mpartp_parse(mpartp, i1, strlen(i1));
    htp_mpartp_parse(mpartp, i2, 1);
    htp_mpartp_parse(mpartp, i3, strlen(i3));
    htp_mpartp_finalize(mpartp);

    htp_multipart_t *body = htp_mpartp_get_multipart(mpartp);
    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_NUL_BYTE);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_INVALID);
}

TEST_F(Multipart, MultipleContentTypeHeadersEvasion) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data\r\n"
        "Content-Type: boundary=0123456789\r\n",
        NULL
    };

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequestThenVerify(headers, data);

    ASSERT_TRUE(tx->request_content_type != NULL);
    ASSERT_TRUE(bstr_cmp_c(tx->request_content_type, "multipart/form-data") == 0);
}

TEST_F(Multipart, BoundaryNormal) {
    char *inputs[] = {
        "multipart/form-data; boundary=----WebKitFormBoundaryT4AfwQCOgIxNVwlD",
        "multipart/form-data; boundary=---------------------------21071316483088",
        "multipart/form-data; boundary=---------------------------7dd13e11c0452",
        "multipart/form-data; boundary=----------2JL5oh7QWEDwyBllIRc7fh",
        "multipart/form-data; boundary=----WebKitFormBoundaryre6zL3b0BelnTY5S",
        NULL
    };

    char *outputs[] = {
        "----WebKitFormBoundaryT4AfwQCOgIxNVwlD",
        "---------------------------21071316483088",
        "---------------------------7dd13e11c0452",
        "----------2JL5oh7QWEDwyBllIRc7fh",
        "----WebKitFormBoundaryre6zL3b0BelnTY5S",
        NULL
    };

    for (size_t i = 0; inputs[i] != NULL; i++) {
        bstr *input = bstr_dup_c(inputs[i]);
        bstr *boundary = NULL;
        uint64_t flags = 0;

        SCOPED_TRACE(inputs[i]);

        htp_status_t rc = htp_mpartp_find_boundary(input, &boundary, &flags);
        ASSERT_EQ(HTP_OK, rc);

        ASSERT_TRUE(boundary != NULL);
        ASSERT_TRUE(bstr_cmp_c(boundary, outputs[i]) == 0);
        ASSERT_EQ(0, flags);

        bstr_free(boundary);
        bstr_free(input);
    }
}

TEST_F(Multipart, BoundaryParsing) {
    char *inputs[] = {
        "multipart/form-data; boundary=1 ",
        "multipart/form-data; boundary=1, boundary=2",
        "multipart/form-data; boundary=\"1\"",
        "multipart/form-data; boundary=\"1\" ",
        "multipart/form-data; boundary=\"1",
        NULL
    };

    char *outputs[] = {
        "1",
        "1",
        "1",
        "1",
        "\"1",
        NULL
    };

    for (size_t i = 0; inputs[i] != NULL; i++) {
        bstr *input = bstr_dup_c(inputs[i]);
        bstr *boundary = NULL;
        uint64_t flags = 0;

        SCOPED_TRACE(inputs[i]);

        htp_status_t rc = htp_mpartp_find_boundary(input, &boundary, &flags);
        ASSERT_EQ(HTP_OK, rc);

        ASSERT_TRUE(boundary != NULL);
        ASSERT_TRUE(bstr_cmp_c(boundary, outputs[i]) == 0);

        bstr_free(boundary);
        bstr_free(input);
    }
}

TEST_F(Multipart, BoundaryInvalid) {
    char *inputs[] = {
        "multipart/form-data boundary=1",
        "multipart/form-data ; boundary=1",
        "multipart/form-data, boundary=1",
        "multipart/form-data , boundary=1",
        "multipart/form-datax; boundary=1",
        "multipart/; boundary=1",
        "multipart; boundary=1",
        "application/octet-stream; boundary=1",
        "boundary=1",
        "multipart/form-data; boundary",
        "multipart/form-data; boundary=",
        "multipart/form-data; boundaryX=",
        "multipart/form-data; boundary=\"\"",
        "multipart/form-data; bounDary=1",
        "multipart/form-data; boundary=1; boundary=2",
        "multipart/form-data; boundary=1 2",
        "multipart/form-data boundary=01234567890123456789012345678901234567890123456789012345678901234567890123456789",
        NULL
    };

    for (size_t i = 0; inputs[i] != NULL; i++) {
        bstr *input = bstr_dup_c(inputs[i]);
        bstr *boundary = NULL;
        uint64_t flags = 0;

        SCOPED_TRACE(inputs[i]);

        htp_status_t rc = htp_mpartp_find_boundary(input, &boundary, &flags);
        ASSERT_TRUE(rc != HTP_ERROR);

        ASSERT_TRUE(flags & HTP_MULTIPART_HBOUNDARY_INVALID);

        bstr_free(boundary);
        bstr_free(input);
    }
}

TEST_F(Multipart, BoundaryUnusual) {
    char *inputs[] = {
        "multipart/form-data; boundary=1 ",
        "multipart/form-data; boundary =1",
        "multipart/form-data; boundary= 1",
        "multipart/form-data; boundary=\"1\"",
        "multipart/form-data; boundary=\" 1 \"",
        //"multipart/form-data; boundary=1-2",
        "multipart/form-data; boundary=\"1?2\"",
        NULL
    };

    for (size_t i = 0; inputs[i] != NULL; i++) {
        bstr *input = bstr_dup_c(inputs[i]);
        bstr *boundary = NULL;
        uint64_t flags = 0;

        SCOPED_TRACE(inputs[i]);

        htp_status_t rc = htp_mpartp_find_boundary(input, &boundary, &flags);
        ASSERT_EQ(HTP_OK, rc);

        ASSERT_TRUE(boundary != NULL);
        ASSERT_TRUE(flags & HTP_MULTIPART_HBOUNDARY_UNUSUAL);

        bstr_free(boundary);
        bstr_free(input);
    }
}

TEST_F(Multipart, CaseInsitiveBoundaryMatching) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=grumpyWizards\r\n",
        NULL
    };

    // The second boundary is all-lowercase and shouldn't be matched on.
    char *data[] = {
        "--grumpyWizards\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n-grumpywizards\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--grumpyWizards\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--grumpyWizards--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(2, htp_list_size(body->parts));
}

TEST_F(Multipart, FoldedContentDisposition) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\";\r\n"
        " filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequestThenVerify(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_FOLDING);
}

TEST_F(Multipart, FoldedContentDisposition2) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\";\r\n"
        "\rfilename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequestThenVerify(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_FOLDING);
}

TEST_F(Multipart, InvalidPartNoData) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // The first part terminates abruptly by the next boundary. This
    // actually works in PHP because its part header parser will
    // consume everything (even boundaries) until the next empty line.

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    htp_multipart_part_t *field1 = (htp_multipart_part_t *) htp_list_get(body->parts, 0);
    ASSERT_TRUE(field1 != NULL);
    ASSERT_EQ(MULTIPART_PART_UNKNOWN, field1->type);

    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INCOMPLETE);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidPartNoContentDisposition) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // A part without a Content-Disposition header.

    char *data[] = {
        "--0123456789\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_UNKNOWN);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidPartMultipleCD) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // When we encounter a part with more than one C-D header, we
    // don't know which one the backend will use. Thus, we raise
    // HTP_MULTIPART_PART_INVALID.

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "Content-Disposition: form-data; name=\"field3\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequestThenVerify(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_REPEATED);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidPartUnknownHeader) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // Unknown C-D header "Unknown".

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "Unknown: Header\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequestThenVerify(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_HEADER_UNKNOWN);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_PART_INVALID);
}

TEST_F(Multipart, InvalidContentDispositionMultipleParams1) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // Two "name" parameters in a C-D header.

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"; name=\"field3\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_CD_PARAM_REPEATED);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_CD_INVALID);
}

TEST_F(Multipart, InvalidContentDispositionMultipleParams2) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // Two "filename" parameters in a C-D header.

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"; filename=\"file2.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_CD_PARAM_REPEATED);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_CD_INVALID);
}

TEST_F(Multipart, InvalidContentDispositionUnknownParam) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    // Unknown C-D parameter "test".

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\"; test=\"param\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_TRUE(body->flags & HTP_MULTIPART_CD_PARAM_UNKNOWN);
    ASSERT_TRUE(body->flags & HTP_MULTIPART_CD_INVALID);
}

TEST_F(Multipart, InvalidContentDispositionSyntax) {
    char *inputs[] = {
        // Parameter value not quoted.
        "form-data; name=field1",
        // Using single quotes around parameter value.
        "form-data; name='field1'",
        // No semicolon after form-data in the C-D header.
        "form-data name=\"field1\"",
        // No semicolon after C-D parameter.
        "form-data; name=\"file1\" filename=\"file.bin\"",
        // Missing terminating quote in C-D parameter value.
        "form-data; name=\"field1",
        // Backslash as the last character in parameter value
        "form-data; name=\"field1\\",
        // C-D header does not begin with "form-data".
        "invalid-syntax; name=\"field1",
        // Escape the terminating double quote.
        "name=\"field1\\\"",
        // Incomplete header.
        "form-data; ",
        // Incomplete header.
        "form-data; name",
        // Incomplete header.
        "form-data; name ",
        // Incomplete header.
        "form-data; name ?",
        // Incomplete header.
        "form-data; name=",
        // Incomplete header.
        "form-data; name= ",
        NULL
    };

    for (size_t i = 0; inputs[i] != NULL; i++) {
        SCOPED_TRACE(inputs[i]);

        mpartp = htp_mpartp_create(cfg, bstr_dup_c("123"), 0 /* flags */);
        
        htp_multipart_part_t *part = (htp_multipart_part_t *) calloc(1, sizeof (htp_multipart_part_t));
        part->headers = htp_table_create(4);
        part->parser = mpartp;

        htp_header_t *h = (htp_header_t *) calloc(1, sizeof (htp_header_t));
        h->name = bstr_dup_c("Content-Disposition");
        h->value = bstr_dup_c(inputs[i]);

        htp_table_add(part->headers, h->name, h);

        htp_status_t rc = htp_mpart_part_parse_c_d(part);
        ASSERT_EQ(HTP_DECLINED, rc);

        body = htp_mpartp_get_multipart(mpartp);
        ASSERT_TRUE(body->flags & HTP_MULTIPART_CD_SYNTAX_INVALID);
        ASSERT_TRUE(body->flags & HTP_MULTIPART_CD_INVALID);

        htp_mpart_part_destroy(part, 0);
        htp_mpartp_destroy(mpartp);
        mpartp = NULL;
    }
}

TEST_F(Multipart, ParamValueEscaping) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"---\\\"---\\\\---\"\r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequest(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);
    ASSERT_EQ(3, htp_list_size(body->parts));

    ASSERT_FALSE(body->flags & HTP_MULTIPART_CD_INVALID);

    htp_multipart_part_t *field1 = (htp_multipart_part_t *) htp_list_get(body->parts, 0);
    ASSERT_TRUE(field1 != NULL);
    ASSERT_EQ(MULTIPART_PART_TEXT, field1->type);
    ASSERT_TRUE(field1->name != NULL);
    ASSERT_TRUE(bstr_cmp_c(field1->name, "---\"---\\---") == 0);
    ASSERT_TRUE(field1->value != NULL);
    ASSERT_TRUE(bstr_cmp_c(field1->value, "ABCDEF") == 0);
}

TEST_F(Multipart, HeaderValueTrim) {
    char *headers[] = {
        "POST / HTTP/1.0\r\n"
        "Content-Type: multipart/form-data; boundary=0123456789\r\n",
        NULL
    };

    char *data[] = {
        "--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field1\" \r\n"
        "\r\n"
        "ABCDEF"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"file.bin\"\r\n"
        "\r\n"
        "FILEDATA"
        "\r\n--0123456789\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "GHIJKL"
        "\r\n--0123456789--",
        NULL
    };

    parseRequestThenVerify(headers, data);

    ASSERT_TRUE(body != NULL);
    ASSERT_TRUE(body->parts != NULL);

    htp_multipart_part_t *field1 = (htp_multipart_part_t *) htp_list_get(body->parts, 0);
    ASSERT_TRUE(field1 != NULL);
    htp_header_t *h = (htp_header_t *) htp_table_get_c(field1->headers, "content-disposition");
    ASSERT_TRUE(h != NULL);
    ASSERT_TRUE(bstr_cmp_c(h->value, "form-data; name=\"field1\" ") == 0);
}
