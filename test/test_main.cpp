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
 *
 * @author Ivan Ristic <ivanr@webkreator.com>
 */

#include <iostream>
#include <gtest/gtest.h>
#include <htp/htp_private.h>
#include "test.h"

class ConnectionParsing : public testing::Test {
protected:

    virtual void SetUp() {
        home = getenv("srcdir");
        if (home == NULL) {
            fprintf(stderr, "This program needs environment variable 'srcdir' set.");
            exit(EXIT_FAILURE);
        }

        cfg = htp_config_create();
        htp_config_set_server_personality(cfg, HTP_SERVER_APACHE_2);
        htp_config_register_urlencoded_parser(cfg);
        htp_config_register_multipart_parser(cfg);
    }

    virtual void TearDown() {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
    }

    htp_connp_t *connp;

    htp_cfg_t *cfg;

    char *home;
};

TEST_F(ConnectionParsing, Get) {
    int rc = test_run(home, "01-get.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));

    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/?p=%20"));

    ASSERT_TRUE(tx->parsed_uri != NULL);

    ASSERT_TRUE(tx->parsed_uri->query != NULL);

    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->query, "p=%20"));

    htp_param_t *p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p->value, " "));
}

TEST_F(ConnectionParsing, ApacheHeaderParsing) {
    int rc = test_run(home, "02-header-test-apache2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(9, htp_table_size(tx->request_headers));

    // Check every header
    int count = 0;
    bstr *key = NULL;
    htp_header_t *h = NULL;

    for (int i = 0, n = htp_table_size(tx->request_headers); i < n; i++) {
        h = (htp_header_t *) htp_table_get_index(tx->request_headers, i, &key);

        switch (count) {
            case 0:
                ASSERT_EQ(0, bstr_cmp_c(h->name, " Invalid-Folding"));
                ASSERT_EQ(0, bstr_cmp_c(h->value, "1"));
                break;
            case 1:
                ASSERT_EQ(0, bstr_cmp_c(h->name, "Valid-Folding"));
                ASSERT_EQ(0, bstr_cmp_c(h->value, "2 2"));
                break;
            case 2:
                ASSERT_EQ(0, bstr_cmp_c(h->name, "Normal-Header"));
                ASSERT_EQ(0, bstr_cmp_c(h->value, "3"));
                break;
            case 3:
                ASSERT_EQ(0, bstr_cmp_c(h->name, "Invalid Header Name"));
                ASSERT_EQ(0, bstr_cmp_c(h->value, "4"));
                break;
            case 4:
                ASSERT_EQ(0, bstr_cmp_c(h->name, "Same-Name-Headers"));
                ASSERT_EQ(0, bstr_cmp_c(h->value, "5, 6"));
                break;
            case 5:
                ASSERT_EQ(0, bstr_cmp_c(h->name, "Empty-Value-Header"));
                ASSERT_EQ(0, bstr_cmp_c(h->value, ""));
                break;
            case 6:
                ASSERT_EQ(0, bstr_cmp_c(h->name, ""));
                ASSERT_EQ(0, bstr_cmp_c(h->value, "8, "));
                break;
            case 7:
                ASSERT_EQ(0, bstr_cmp_c(h->name, "Header-With-LWS-After"));
                ASSERT_EQ(0, bstr_cmp_c(h->value, "9"));
                break;
            case 8:
                ASSERT_EQ(0, bstr_cmp_c(h->name, "Header-With-NUL"));
                ASSERT_EQ(0, bstr_cmp_c(h->value, "BEFORE"));
                break;
        }

        count++;
    }
}

TEST_F(ConnectionParsing, PostUrlencoded) {
    int rc = test_run(home, "03-post-urlencoded.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    htp_param_t *p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p->value, "0123456789"));
}

TEST_F(ConnectionParsing, PostUrlencodedChunked) {
    int rc = test_run(home, "04-post-urlencoded-chunked.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    htp_param_t *p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p->value, "0123456789"));

    ASSERT_EQ(25, tx->request_message_len);

    ASSERT_EQ(12, tx->request_entity_len);
}

TEST_F(ConnectionParsing, Expect) {
    int rc = test_run(home, "05-expect.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
}

TEST_F(ConnectionParsing, UriNormal) {
    int rc = test_run(home, "06-uri-normal.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
}

TEST_F(ConnectionParsing, PipelinedConn) {
    int rc = test_run(home, "07-pipelined-connection.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));

    ASSERT_TRUE(connp->conn->flags & HTP_CONN_PIPELINED);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
}

TEST_F(ConnectionParsing, NotPipelinedConn) {
    int rc = test_run(home, "08-not-pipelined-connection.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));

    ASSERT_FALSE(connp->conn->flags & HTP_CONN_PIPELINED);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_FALSE(tx->flags & HTP_MULTI_PACKET_HEAD);
}

TEST_F(ConnectionParsing, MultiPacketRequest) {
    int rc = test_run(home, "09-multi-packet-request-head.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_MULTI_PACKET_HEAD);
}

TEST_F(ConnectionParsing, HeaderHostParsing) {
    int rc = test_run(home, "10-host-in-headers.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(4, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx1 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx1 != NULL);
    ASSERT_TRUE(tx1->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx1->request_hostname, "www.example.com"));

    htp_tx_t *tx2 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 1);
    ASSERT_TRUE(tx2 != NULL);
    ASSERT_TRUE(tx2->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx2->request_hostname, "www.example.com."));

    htp_tx_t *tx3 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 2);
    ASSERT_TRUE(tx3 != NULL);
    ASSERT_TRUE(tx3->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx3->request_hostname, "www.example.com"));

    htp_tx_t *tx4 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 3);
    ASSERT_TRUE(tx4 != NULL);
    ASSERT_TRUE(tx4->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx4->request_hostname, "www.example.com"));
}

TEST_F(ConnectionParsing, ResponseWithoutContentLength) {
    int rc = test_run(home, "11-response-stream-closure.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));
}

TEST_F(ConnectionParsing, FailedConnectRequest) {
    int rc = test_run(home, "12-connect-request.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));

    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "CONNECT"));

    ASSERT_EQ(405, tx->response_status_number);
}

TEST_F(ConnectionParsing, CompressedResponseContentType) {
    int rc = test_run(home, "13-compressed-response-gzip-ct.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));

    ASSERT_EQ(187, tx->response_message_len);

    ASSERT_EQ(225, tx->response_entity_len);
}

TEST_F(ConnectionParsing, CompressedResponseChunked) {
    int rc = test_run(home, "14-compressed-response-gzip-chunked.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));

    ASSERT_EQ(28261, tx->response_message_len);

    ASSERT_EQ(159590, tx->response_entity_len);
}

TEST_F(ConnectionParsing, SuccessfulConnectRequest) {
    int rc = test_run(home, "15-connect-complete.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));

    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "CONNECT"));

    ASSERT_EQ(200, tx->response_status_number);
}

TEST_F(ConnectionParsing, ConnectRequestWithExtraData) {
    int rc = test_run(home, "16-connect-extra.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx1 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx1 != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx1));

    htp_tx_t *tx2 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 1);
    ASSERT_TRUE(tx2 != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx2));
}

TEST_F(ConnectionParsing, Multipart) {
    int rc = test_run(home, "17-multipart-1.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));

    htp_param_t *field1 = htp_tx_req_get_param(tx, "field1", 6);
    ASSERT_TRUE(field1 != NULL);
    ASSERT_EQ(0, bstr_cmp_c(field1->value, "0123456789"));

    htp_param_t *field2 = htp_tx_req_get_param(tx, "field2", 6);
    ASSERT_TRUE(field2 != NULL);
    ASSERT_EQ(0, bstr_cmp_c(field2->value, "9876543210"));
}

TEST_F(ConnectionParsing, CompressedResponseDeflate) {
    int rc = test_run(home, "18-compressed-response-deflate.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));

    ASSERT_EQ(755, tx->response_message_len);

    ASSERT_EQ(1433, tx->response_entity_len);
}

TEST_F(ConnectionParsing, UrlEncoded) {
    int rc = test_run(home, "19-urlencoded-test.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));

    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "POST"));
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/?p=1&q=2"));

    htp_param_t *body_p = htp_tx_req_get_param_ex(tx, HTP_SOURCE_BODY, "p", 1);
    ASSERT_TRUE(body_p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(body_p->value, "3"));

    htp_param_t *body_q = htp_tx_req_get_param_ex(tx, HTP_SOURCE_BODY, "q", 1);
    ASSERT_TRUE(body_q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(body_q->value, "4"));

    htp_param_t *body_z = htp_tx_req_get_param_ex(tx, HTP_SOURCE_BODY, "z", 1);
    ASSERT_TRUE(body_z != NULL);
    ASSERT_EQ(0, bstr_cmp_c(body_z->value, "5"));
}

TEST_F(ConnectionParsing, AmbiguousHost) {
    int rc = test_run(home, "20-ambiguous-host.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(4, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx1 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx1 != NULL);
    ASSERT_TRUE(htp_tx_is_complete(tx1));
    ASSERT_FALSE(tx1->flags & HTP_HOST_AMBIGUOUS);

    htp_tx_t *tx2 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 1);
    ASSERT_TRUE(tx2 != NULL);
    ASSERT_TRUE(htp_tx_is_complete(tx2));
    ASSERT_TRUE(tx2->flags & HTP_HOST_AMBIGUOUS);
    ASSERT_TRUE(tx2->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx2->request_hostname, "example.com"));

    htp_tx_t *tx3 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 2);
    ASSERT_TRUE(tx3 != NULL);
    ASSERT_TRUE(htp_tx_is_complete(tx3));
    ASSERT_FALSE(tx3->flags & HTP_HOST_AMBIGUOUS);
    ASSERT_TRUE(tx3->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx3->request_hostname, "www.example.com"));
    ASSERT_EQ(8001, tx3->request_port_number);

    htp_tx_t *tx4 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 3);
    ASSERT_TRUE(tx4 != NULL);
    ASSERT_TRUE(htp_tx_is_complete(tx4));
    ASSERT_TRUE(tx4->flags & HTP_HOST_AMBIGUOUS);
    ASSERT_TRUE(tx4->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx4->request_hostname, "www.example.com"));
    ASSERT_EQ(8002, tx4->request_port_number);
}

TEST_F(ConnectionParsing, Http_0_9) {
    int rc = test_run(home, "21-http09.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));
    ASSERT_FALSE(connp->conn->flags & HTP_CONN_HTTP_0_9_EXTRA);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
}

TEST_F(ConnectionParsing, PhpParamProcessing) {
    cfg->parameter_processor = htp_php_parameter_processor;

    int rc = test_run(home, "22-php-param-processing.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    htp_param_t *p1 = htp_tx_req_get_param(tx, "p_q_", 4);
    ASSERT_TRUE(p1 != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p1->value, "1"));

    htp_param_t *p2 = htp_tx_req_get_param(tx, "q", 1);
    ASSERT_TRUE(p2 != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p2->value, "2"));

    htp_param_t *p3 = htp_tx_req_get_param(tx, "z_w", 3);
    ASSERT_TRUE(p3 != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p3->value, "3"));
}

TEST_F(ConnectionParsing, Http11HostMissing) {
    int rc = test_run(home, "22-http_1_1-host_missing", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_HOST_MISSING);
}

TEST_F(ConnectionParsing, Http_0_9_Multiple) {
    int rc = test_run(home, "23-http09-multiple.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));
    ASSERT_TRUE(connp->conn->flags & HTP_CONN_HTTP_0_9_EXTRA);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
}

TEST_F(ConnectionParsing, Http_0_9_Explicit) {
    int rc = test_run(home, "24-http09-explicit.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
    ASSERT_EQ(0, tx->is_protocol_0_9);
}

TEST_F(ConnectionParsing, SmallChunks) {
    int rc = test_run(home, "25-small-chunks.t", cfg, &connp);
    ASSERT_GE(rc, 0);
}

static int ConnectionParsing_RequestHeaderData_REQUEST_HEADER_DATA(htp_tx_data_t *d) {
    static int counter = 0;

    switch (counter) {
        case 0:
            if (!((d->len == 11) && (memcmp(d->data, "User-Agent:", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 0");
                counter = -1;
            }
            break;

        case 1:
            if (!((d->len == 5) && (memcmp(d->data, " Test", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 1");
                counter = -1;
            }
            break;

        case 2:
            if (!((d->len == 5) && (memcmp(d->data, " User", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 2");
                counter = -1;
            }
            break;

        case 3:
            if (!((d->len == 30) && (memcmp(d->data, " Agent\nHost: www.example.com\n\n", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 3");
                counter = -1;
            }
            break;

        default:
            if (counter >= 0) {
                SCOPED_TRACE("Seen more than 4 chunks");
                counter = -1;
            }
            break;
    }

    if (counter >= 0) {
        counter++;
    }

    htp_tx_set_user_data(d->tx, &counter);

    return HTP_OK;
}

TEST_F(ConnectionParsing, RequestHeaderData) {
    htp_config_register_request_header_data(cfg, ConnectionParsing_RequestHeaderData_REQUEST_HEADER_DATA);

    int rc = test_run(home, "26-request-headers-raw.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    int *counter = (int *) htp_tx_get_user_data(tx);
    ASSERT_TRUE(counter != NULL);
    ASSERT_EQ(4, *counter);
}

static int ConnectionParsing_RequestTrailerData_REQUEST_TRAILER_DATA(htp_tx_data_t *d) {
    static int counter = 0;

    switch (counter) {
        case 0:
            if (!((d->len == 7) && (memcmp(d->data, "Cookie:", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 0");
                counter = -1;
            }
            break;

        case 1:
            if (!((d->len == 6) && (memcmp(d->data, " 2\r\n\r\n", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 1");
                counter = -2;
            }
            break;

        default:
            if (counter >= 0) {
                SCOPED_TRACE("Seen more than 4 chunks");
                counter = -3;
            }
            break;
    }

    if (counter >= 0) {
        counter++;
    }

    htp_tx_set_user_data(d->tx, &counter);

    return HTP_OK;
}

TEST_F(ConnectionParsing, RequestTrailerData) {
    htp_config_register_request_trailer_data(cfg, ConnectionParsing_RequestTrailerData_REQUEST_TRAILER_DATA);

    int rc = test_run(home, "27-request-trailer-raw.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    int *counter = (int *) htp_tx_get_user_data(tx);
    ASSERT_TRUE(counter != NULL);
    ASSERT_EQ(2, *counter);
}

static int ConnectionParsing_ResponseHeaderData_RESPONSE_HEADER_DATA(htp_tx_data_t *d) {
    static int counter = 0;

    switch (counter) {
        case 0:
            if (!((d->len == 5) && (memcmp(d->data, "Date:", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 0");
                counter = -1;
            }
            break;

        case 1:
            if (!((d->len == 5) && (memcmp(d->data, " Mon,", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 1");
                counter = -2;
            }
            break;

        case 2:
            if (!((d->len == 34) && (memcmp(d->data, " 31 Aug 2009 20:25:50 GMT\r\nServer:", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 2");
                counter = -3;
            }
            break;

        case 3:
            if (!((d->len == 83) && (memcmp(d->data, " Apache\r\nConnection: close\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 3");
                counter = -4;
            }
            break;

        default:
            if (counter >= 0) {
                SCOPED_TRACE("Seen more than 4 chunks");
                counter = -5;
            }
            break;
    }

    if (counter >= 0) {
        counter++;
    }

    htp_tx_set_user_data(d->tx, &counter);

    return HTP_OK;
}

TEST_F(ConnectionParsing, ResponseHeaderData) {
    htp_config_register_response_header_data(cfg, ConnectionParsing_ResponseHeaderData_RESPONSE_HEADER_DATA);

    int rc = test_run(home, "28-response-headers-raw.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    int *counter = (int *) htp_tx_get_user_data(tx);
    ASSERT_TRUE(counter != NULL);
    ASSERT_EQ(4, *counter);
}

static int ConnectionParsing_ResponseTrailerData_RESPONSE_TRAILER_DATA(htp_tx_data_t *d) {
    static int counter = 0;

    switch (counter) {
        case 0:
            if (!((d->len == 11) && (memcmp(d->data, "Set-Cookie:", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 0");
                counter = -1;
            }
            break;

        case 1:
            if (!((d->len == 6) && (memcmp(d->data, " name=", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 1");
                counter = -2;
            }
            break;

        case 2:
            if (!((d->len == 22) && (memcmp(d->data, "value\r\nAnother-Header:", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 1");
                counter = -3;
            }
            break;

        case 3:
            if (!((d->len == 17) && (memcmp(d->data, " Header-Value\r\n\r\n", d->len) == 0))) {
                SCOPED_TRACE("Mismatch in chunk 1");
                counter = -4;
            }
            break;

        default:
            if (counter >= 0) {
                SCOPED_TRACE("Seen more than 4 chunks");
                counter = -5;
            }
            break;
    }

    if (counter >= 0) {
        counter++;
    }

    htp_tx_set_user_data(d->tx, &counter);

    return HTP_OK;
}

TEST_F(ConnectionParsing, ResponseTrailerData) {
    htp_config_register_response_trailer_data(cfg, ConnectionParsing_ResponseTrailerData_RESPONSE_TRAILER_DATA);

    int rc = test_run(home, "29-response-trailer-raw.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    int *counter = (int *) htp_tx_get_user_data(tx);
    ASSERT_TRUE(counter != NULL);
    ASSERT_EQ(4, *counter);
}

TEST_F(ConnectionParsing, GetIPv6) {
    int rc = test_run(home, "30-get-ipv6.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->request_method != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));   

    ASSERT_TRUE(tx->request_uri != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "http://[::1]:8080/?p=%20"));

    ASSERT_TRUE(tx->parsed_uri != NULL);
    
    ASSERT_TRUE(tx->parsed_uri->hostname != NULL);   
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->hostname, "[::1]"));
    ASSERT_EQ(8080, tx->parsed_uri->port_number);

    ASSERT_TRUE(tx->parsed_uri->query != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->query, "p=%20"));

    htp_param_t *p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(p != NULL);    
    ASSERT_TRUE(p->value != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p->value, " "));
}

TEST_F(ConnectionParsing, GetRequestLineNul) {
    int rc = test_run(home, "31-get-request-line-nul.t", cfg, &connp);
    ASSERT_GE(rc, 0);
    
    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
    
    ASSERT_TRUE(tx->request_uri != NULL);   

    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/?p=%20"));   
}

TEST_F(ConnectionParsing, InvalidHostname1) {
    int rc = test_run(home, "32-invalid-hostname.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_HOSTH_INVALID);
    ASSERT_TRUE(tx->flags & HTP_HOSTU_INVALID);
    ASSERT_TRUE(tx->flags & HTP_HOST_INVALID);
}

TEST_F(ConnectionParsing, InvalidHostname2) {
    int rc = test_run(home, "33-invalid-hostname.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_FALSE(tx->flags & HTP_HOSTH_INVALID);
    ASSERT_TRUE(tx->flags & HTP_HOSTU_INVALID);
    ASSERT_TRUE(tx->flags & HTP_HOST_INVALID);
}

TEST_F(ConnectionParsing, InvalidHostname3) {
    int rc = test_run(home, "34-invalid-hostname.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_HOSTH_INVALID);
    ASSERT_FALSE(tx->flags & HTP_HOSTU_INVALID);
    ASSERT_TRUE(tx->flags & HTP_HOST_INVALID);
}

TEST_F(ConnectionParsing, API_connp_get_connection) {
    int rc = test_run(home, "34-invalid-hostname.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(connp->conn, htp_connp_get_connection(connp));
}

TEST_F(ConnectionParsing, EarlyResponse) {
    int rc = test_run(home, "35-early-response.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(htp_tx_is_complete(tx));
}

TEST_F(ConnectionParsing, InvalidRequest1) {
    int rc = test_run(home, "36-invalid-request-1.t", cfg, &connp);
    ASSERT_LT(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_HEADERS, tx->request_progress);

    ASSERT_TRUE(tx->flags & HTP_REQUEST_INVALID);
    ASSERT_TRUE(tx->flags & HTP_REQUEST_INVALID_C_L);

    ASSERT_TRUE(tx->request_hostname != NULL);
}

TEST_F(ConnectionParsing, InvalidRequest2) {
    int rc = test_run(home, "37-invalid-request-2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    
    ASSERT_TRUE(tx->flags & HTP_REQUEST_SMUGGLING);

    ASSERT_TRUE(tx->request_hostname != NULL);
}

TEST_F(ConnectionParsing, InvalidRequest3) {
    int rc = test_run(home, "38-invalid-request-3.t", cfg, &connp);
    ASSERT_LT(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_HEADERS, tx->request_progress);

    ASSERT_TRUE(tx->flags & HTP_REQUEST_INVALID);
    ASSERT_TRUE(tx->flags & HTP_REQUEST_INVALID_T_E);    

    ASSERT_TRUE(tx->request_hostname != NULL);
}

TEST_F(ConnectionParsing, AutoDestroyCrash) {
    htp_config_set_tx_auto_destroy(cfg, 1);
    
    int rc = test_run(home, "39-auto-destroy-crash.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(4, htp_list_size(connp->conn->transactions));
}
