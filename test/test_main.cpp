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

TEST_F(ConnectionParsing, AdHoc) {
    int rc = test_run(home, "00-adhoc.t", cfg, &connp);
    ASSERT_GE(rc, 0);
}

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

    htp_tx_t *tx1 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx1 != NULL);
    htp_param_t *p = htp_tx_req_get_param(tx1, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p->value, "0123456789"));

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx1->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx1->response_progress);

    htp_header_t *h = (htp_header_t *)htp_table_get_c(tx1->response_headers, "Server");
    ASSERT_TRUE(h != NULL);
    ASSERT_TRUE(h->value != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h->value, "Apache"));

    htp_tx_t *tx2 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 1);
    ASSERT_TRUE(tx2 != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx2->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx2->response_progress);

    h = (htp_header_t *)htp_table_get_c(tx2->response_headers, "Server");
    ASSERT_TRUE(h != NULL);
    ASSERT_TRUE(h->value != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h->value, "Apache"));
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

    // The interim header from the 100 response should not be among the final headers.
    htp_header_t *h = (htp_header_t *) htp_table_get_c(tx->request_headers, "Header1");
    ASSERT_TRUE(h == NULL);
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

    // TODO: Update the test_run() function to provide better
    //       simulation of real traffic. At the moment, it does not
    //       invoke inbound parsing after outbound parsing returns
    //       HTP_DATA_OTHER, which is why the check below fails.
    //ASSERT_TRUE(htp_tx_is_complete(tx));

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

    ASSERT_EQ(5, htp_list_size(connp->conn->transactions));

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

    htp_tx_t *tx5 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 4);
    ASSERT_TRUE(tx5 != NULL);
    ASSERT_TRUE(htp_tx_is_complete(tx5));
    ASSERT_FALSE(tx5->flags & HTP_HOST_AMBIGUOUS);
    ASSERT_TRUE(tx5->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx5->request_hostname, "www.example.com"));
    ASSERT_EQ(80, tx5->request_port_number);
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
    int rc = test_run(home, "36-invalid-request-1-invalid-c-l.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error.

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_HEADERS, tx->request_progress);

    ASSERT_TRUE(tx->flags & HTP_REQUEST_INVALID);
    ASSERT_TRUE(tx->flags & HTP_REQUEST_INVALID_C_L);

    ASSERT_TRUE(tx->request_hostname != NULL);
}

TEST_F(ConnectionParsing, InvalidRequest2) {
    int rc = test_run(home, "37-invalid-request-2-t-e-and-c-l.t", cfg, &connp);
    ASSERT_GE(rc, 0); // No error, flags only.

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_TRUE(tx->flags & HTP_REQUEST_SMUGGLING);

    ASSERT_TRUE(tx->request_hostname != NULL);
}

TEST_F(ConnectionParsing, InvalidRequest3) {
    int rc = test_run(home, "38-invalid-request-3-invalid-t-e.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error.

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

TEST_F(ConnectionParsing, AuthBasic) {
    int rc = test_run(home, "40-auth-basic.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_EQ(HTP_AUTH_BASIC, tx->request_auth_type);

    ASSERT_TRUE(tx->request_auth_username != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_auth_username, "ivanr"));

    ASSERT_TRUE(tx->request_auth_password != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_auth_password, "secret"));
}

TEST_F(ConnectionParsing, AuthDigest) {
    int rc = test_run(home, "41-auth-digest.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_EQ(HTP_AUTH_DIGEST, tx->request_auth_type);

    ASSERT_TRUE(tx->request_auth_username != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_auth_username, "ivanr"));

    ASSERT_TRUE(tx->request_auth_password == NULL);
}

TEST_F(ConnectionParsing, Http_0_9_MethodOnly) {
    int rc = test_run(home, "42-http_0_9-method_only.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_TRUE(tx->request_method != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "HELLO"));

    ASSERT_TRUE(tx->request_uri == NULL);

    ASSERT_EQ(1, tx->is_protocol_0_9);
}

TEST_F(ConnectionParsing, InvalidProtocol) {
    int rc = test_run(home, "43-invalid-protocol.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_EQ(HTP_PROTOCOL_INVALID, tx->request_protocol_number);
}

TEST_F(ConnectionParsing, AuthBasicInvalid) {
    int rc = test_run(home, "44-auth-basic-invalid.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_EQ(HTP_AUTH_BASIC, tx->request_auth_type);

    ASSERT_TRUE(tx->request_auth_username == NULL);

    ASSERT_TRUE(tx->request_auth_password == NULL);

    ASSERT_TRUE(tx->flags & HTP_AUTH_INVALID);
}

TEST_F(ConnectionParsing, AuthDigestUnquotedUsername) {
    int rc = test_run(home, "45-auth-digest-unquoted-username.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_EQ(HTP_AUTH_DIGEST, tx->request_auth_type);

    ASSERT_TRUE(tx->request_auth_username == NULL);

    ASSERT_TRUE(tx->request_auth_password == NULL);

    ASSERT_TRUE(tx->flags & HTP_AUTH_INVALID);
}

TEST_F(ConnectionParsing, AuthDigestInvalidUsername1) {
    int rc = test_run(home, "46-auth-digest-invalid-username.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_EQ(HTP_AUTH_DIGEST, tx->request_auth_type);

    ASSERT_TRUE(tx->request_auth_username == NULL);

    ASSERT_TRUE(tx->request_auth_password == NULL);

    ASSERT_TRUE(tx->flags & HTP_AUTH_INVALID);
}

TEST_F(ConnectionParsing, AuthUnrecognized) {
    int rc = test_run(home, "47-auth-unrecognized.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_EQ(HTP_AUTH_UNRECOGNIZED, tx->request_auth_type);

    ASSERT_TRUE(tx->request_auth_username == NULL);

    ASSERT_TRUE(tx->request_auth_password == NULL);
}

TEST_F(ConnectionParsing, InvalidResponseHeaders1) {
    int rc = test_run(home, "48-invalid-response-headers-1.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);

    ASSERT_EQ(8, htp_table_size(tx->response_headers));

    htp_header_t *h_empty = (htp_header_t *) htp_table_get_c(tx->response_headers, "");
    ASSERT_TRUE(h_empty != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_empty->value, "No Colon"));
    ASSERT_TRUE(h_empty->flags & HTP_FIELD_INVALID);
    ASSERT_TRUE(h_empty->flags & HTP_FIELD_UNPARSEABLE);

    htp_header_t *h_lws = (htp_header_t *) htp_table_get_c(tx->response_headers, "Lws");
    ASSERT_TRUE(h_lws != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_lws->value, "After Header Name"));
    ASSERT_TRUE(h_lws->flags & HTP_FIELD_INVALID);

    htp_header_t *h_nottoken = (htp_header_t *) htp_table_get_c(tx->response_headers, "Header@Name");
    ASSERT_TRUE(h_nottoken != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_nottoken->value, "Not Token"));
    ASSERT_TRUE(h_nottoken->flags & HTP_FIELD_INVALID);
}

TEST_F(ConnectionParsing, InvalidResponseHeaders2) {
    int rc = test_run(home, "49-invalid-response-headers-2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);

    ASSERT_EQ(6, htp_table_size(tx->response_headers));

    htp_header_t *h_empty = (htp_header_t *) htp_table_get_c(tx->response_headers, "");
    ASSERT_TRUE(h_empty != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_empty->value, "Empty Name"));
    ASSERT_TRUE(h_empty->flags & HTP_FIELD_INVALID);
}

TEST_F(ConnectionParsing, Util) {
    int rc = test_run(home, "50-util.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    char *in_state = htp_connp_in_state_as_string(tx->connp);
    ASSERT_TRUE(in_state != NULL);

    char *out_state = htp_connp_out_state_as_string(tx->connp);
    ASSERT_TRUE(out_state != NULL);

    char *request_progress = htp_tx_request_progress_as_string(tx);
    ASSERT_TRUE(request_progress != NULL);

    char *response_progress = htp_tx_response_progress_as_string(tx);
    ASSERT_TRUE(response_progress != NULL);

    FILE *null = fopen("/dev/null", "w");
    ASSERT_TRUE(null != NULL);

    fprint_bstr(null, "test", NULL);

    fprint_bstr(null, "test", tx->request_line);

    fprint_raw_data(null, "test", bstr_ptr(tx->request_line), bstr_len(tx->request_line));

    fprint_raw_data_ex(null, "test", bstr_ptr(tx->request_line), 0, bstr_len(tx->request_line));

    // Message too long.
    tx->connp->cfg->log_level = HTP_LOG_ERROR;
    char long_message[1300];
    for (size_t i = 0; i < 1299; i++) {
        long_message[i] = 'X';
    }
    long_message[1299] = '\0';

    htp_log(tx->connp, __FILE__, __LINE__, HTP_LOG_ERROR, 0, long_message);
    ASSERT_TRUE(tx->connp->last_error != NULL);
    ASSERT_TRUE(tx->connp->last_error->msg != NULL);
    ASSERT_EQ(1023, strlen(tx->connp->last_error->msg));
    ASSERT_EQ('+', tx->connp->last_error->msg[1022]);

    // A message that should not be logged.
    size_t log_message_count = htp_list_size(tx->connp->conn->messages);
    tx->connp->cfg->log_level = HTP_LOG_NONE;
    htp_log(tx->connp, __FILE__, __LINE__, HTP_LOG_ERROR, 0, "Log message");
    ASSERT_EQ(log_message_count, htp_list_size(tx->connp->conn->messages));
}

TEST_F(ConnectionParsing, GetIPv6Invalid) {
    int rc = test_run(home, "51-get-ipv6-invalid.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->request_method != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));

    ASSERT_TRUE(tx->request_uri != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "http://[::1:8080/?p=%20"));

    ASSERT_TRUE(tx->parsed_uri != NULL);

    ASSERT_TRUE(tx->parsed_uri->hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->hostname, "[::1:8080"));
}

TEST_F(ConnectionParsing, InvalidPath) {
    int rc = test_run(home, "52-invalid-path.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->request_method != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));

    ASSERT_TRUE(tx->request_uri != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "invalid/path?p=%20"));

    ASSERT_TRUE(tx->parsed_uri != NULL);

    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "invalid/path"));
}

TEST_F(ConnectionParsing, PathUtf8_None) {
    int rc = test_run(home, "53-path-utf8-none.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_FALSE(tx->flags & HTP_PATH_UTF8_VALID);
    ASSERT_FALSE(tx->flags & HTP_PATH_UTF8_OVERLONG);
    ASSERT_FALSE(tx->flags & HTP_PATH_HALF_FULL_RANGE);
}

TEST_F(ConnectionParsing, PathUtf8_Valid) {
    int rc = test_run(home, "54-path-utf8-valid.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_VALID);
}

TEST_F(ConnectionParsing, PathUtf8_Overlong2) {
    int rc = test_run(home, "55-path-utf8-overlong-2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_OVERLONG);
}

TEST_F(ConnectionParsing, PathUtf8_Overlong3) {
    int rc = test_run(home, "56-path-utf8-overlong-3.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_OVERLONG);
}

TEST_F(ConnectionParsing, PathUtf8_Overlong4) {
    int rc = test_run(home, "57-path-utf8-overlong-4.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_OVERLONG);
}

TEST_F(ConnectionParsing, PathUtf8_Invalid) {
    int rc = test_run(home, "58-path-utf8-invalid.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_INVALID);
    ASSERT_FALSE(tx->flags & HTP_PATH_UTF8_VALID);
}

TEST_F(ConnectionParsing, PathUtf8_FullWidth) {
    int rc = test_run(home, "59-path-utf8-fullwidth.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_HALF_FULL_RANGE);
}

TEST_F(ConnectionParsing, PathUtf8_Decode_Valid) {
    htp_config_set_utf8_convert_bestfit(cfg, HTP_DECODER_URL_PATH, 1);

    int rc = test_run(home, "54-path-utf8-valid.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->parsed_uri != NULL);
    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/Ristic.txt"));
}

TEST_F(ConnectionParsing, PathUtf8_Decode_Overlong2) {
    htp_config_set_utf8_convert_bestfit(cfg, HTP_DECODER_URL_PATH, 1);

    int rc = test_run(home, "55-path-utf8-overlong-2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_OVERLONG);

    ASSERT_TRUE(tx->parsed_uri != NULL);
    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/&.txt"));
}

TEST_F(ConnectionParsing, PathUtf8_Decode_Overlong3) {
    htp_config_set_utf8_convert_bestfit(cfg, HTP_DECODER_URL_PATH, 1);

    int rc = test_run(home, "56-path-utf8-overlong-3.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_OVERLONG);

    ASSERT_TRUE(tx->parsed_uri != NULL);
    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/&.txt"));
}

TEST_F(ConnectionParsing, PathUtf8_Decode_Overlong4) {
    htp_config_set_utf8_convert_bestfit(cfg, HTP_DECODER_URL_PATH, 1);

    int rc = test_run(home, "57-path-utf8-overlong-4.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_OVERLONG);

    ASSERT_TRUE(tx->parsed_uri != NULL);
    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/&.txt"));
}

TEST_F(ConnectionParsing, PathUtf8_Decode_Invalid) {
    htp_config_set_utf8_convert_bestfit(cfg, HTP_DECODER_URL_PATH, 1);

    int rc = test_run(home, "58-path-utf8-invalid.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_UTF8_INVALID);
    ASSERT_FALSE(tx->flags & HTP_PATH_UTF8_VALID);

    ASSERT_TRUE(tx->parsed_uri != NULL);
    ASSERT_TRUE(tx->parsed_uri->path != NULL);

    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/Ristic?.txt"));
}

TEST_F(ConnectionParsing, PathUtf8_Decode_FullWidth) {
    htp_config_set_utf8_convert_bestfit(cfg, HTP_DECODER_URL_PATH, 1);

    int rc = test_run(home, "59-path-utf8-fullwidth.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->flags & HTP_PATH_HALF_FULL_RANGE);

    ASSERT_TRUE(tx->parsed_uri != NULL);
    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/&.txt"));
}

TEST_F(ConnectionParsing, RequestCookies) {
    int rc = test_run(home, "60-request-cookies.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(3, htp_table_size(tx->request_cookies));

    bstr *key = NULL;
    bstr *value = NULL;

    value = (bstr *) htp_table_get_index(tx->request_cookies, 0, &key);
    ASSERT_TRUE(key != NULL);
    ASSERT_TRUE(value != NULL);
    ASSERT_EQ(0, bstr_cmp_c(key, "p"));
    ASSERT_EQ(0, bstr_cmp_c(value, "1"));

    value = (bstr *) htp_table_get_index(tx->request_cookies, 1, &key);
    ASSERT_TRUE(key != NULL);
    ASSERT_TRUE(value != NULL);
    ASSERT_EQ(0, bstr_cmp_c(key, "q"));
    ASSERT_EQ(0, bstr_cmp_c(value, "2"));

    value = (bstr *) htp_table_get_index(tx->request_cookies, 2, &key);
    ASSERT_TRUE(key != NULL);
    ASSERT_TRUE(value != NULL);
    ASSERT_EQ(0, bstr_cmp_c(key, "z"));
    ASSERT_EQ(0, bstr_cmp_c(value, ""));
}

TEST_F(ConnectionParsing, EmptyLineBetweenRequests) {
    int rc = test_run(home, "61-empty-line-between-requests.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 1);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(1, tx->request_ignored_lines);
}

TEST_F(ConnectionParsing, PostNoBody) {
    int rc = test_run(home, "62-post-no-body.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx1 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx1 != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx1->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx1->response_progress);

    htp_tx_t *tx2 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 1);
    ASSERT_TRUE(tx2 != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx2->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx2->response_progress);
}

TEST_F(ConnectionParsing, PostChunkedInvalid1) {
    int rc = test_run(home, "63-post-chunked-invalid-1.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error.
}

TEST_F(ConnectionParsing, PostChunkedInvalid2) {
    int rc = test_run(home, "64-post-chunked-invalid-2.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error.
}

TEST_F(ConnectionParsing, PostChunkedInvalid3) {
    int rc = test_run(home, "65-post-chunked-invalid-3.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error.
}

TEST_F(ConnectionParsing, PostChunkedSplitChunk) {
    int rc = test_run(home, "66-post-chunked-split-chunk.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    htp_param_t *p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_TRUE(p->value != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p->value, "0123456789"));
}

TEST_F(ConnectionParsing, LongRequestLine1) {
    int rc = test_run(home, "67-long-request-line.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/0123456789/0123456789/"));
}

TEST_F(ConnectionParsing, LongRequestLine2) {
    htp_config_set_field_limits(cfg, 0, 16);

    int rc = test_run(home, "67-long-request-line.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error.

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_LINE, tx->request_progress);
}

TEST_F(ConnectionParsing, InvalidRequestHeader) {
    int rc = test_run(home, "68-invalid-request-header.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    htp_header_t *h = (htp_header_t *) htp_table_get_c(tx->request_headers, "Header-With-NUL");
    ASSERT_TRUE(h != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h->value, "BEFORE"));
}

TEST_F(ConnectionParsing, TestGenericPersonality) {
    htp_config_set_server_personality(cfg, HTP_SERVER_IDS);

    int rc = test_run(home, "02-header-test-apache2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
}

TEST_F(ConnectionParsing, LongResponseHeader) {
    htp_config_set_field_limits(cfg, 0, 16);

    int rc = test_run(home, "69-long-response-header.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error.

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_HEADERS, tx->response_progress);
}

TEST_F(ConnectionParsing, ResponseInvalidChunkLength) {
    int rc = test_run(home, "70-response-invalid-chunk-length.t", cfg, &connp);
    ASSERT_EQ(rc, 1); // Expect success as we're very liberal
}

TEST_F(ConnectionParsing, ResponseSplitChunk) {
    int rc = test_run(home, "71-response-split-chunk.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));
    
    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);
}

TEST_F(ConnectionParsing, ResponseBody) {
    int rc = test_run(home, "72-response-split-body.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);
}

TEST_F(ConnectionParsing, ResponseContainsTeAndCl) {
    int rc = test_run(home, "73-response-te-and-cl.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);

    ASSERT_TRUE(tx->flags & HTP_REQUEST_SMUGGLING);
}

TEST_F(ConnectionParsing, ResponseMultipleCl) {
    int rc = test_run(home, "74-response-multiple-cl.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);

    ASSERT_TRUE(tx->flags & HTP_REQUEST_SMUGGLING);

    htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->response_headers, "Content-Length");
    ASSERT_TRUE(h != NULL);
    ASSERT_TRUE(h->value != NULL);
    ASSERT_TRUE(h->flags & HTP_FIELD_REPEATED);

    ASSERT_EQ(0, bstr_cmp_c(h->value, "12"));
}

TEST_F(ConnectionParsing, ResponseMultipleClMismatch) {
    int rc = test_run(home, "88-response-multiple-cl-mismatch.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_HEADERS, tx->response_progress);
}

TEST_F(ConnectionParsing, ResponseInvalidCl) {
    int rc = test_run(home, "75-response-invalid-cl.t", cfg, &connp);
    ASSERT_LT(rc, 0); // Expect error.

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_HEADERS, tx->response_progress);

    ASSERT_FALSE(tx->flags & HTP_REQUEST_SMUGGLING);
}

TEST_F(ConnectionParsing, ResponseNoBody) {
    int rc = test_run(home, "76-response-no-body.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx1 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx1 != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx1->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx1->response_progress);

    htp_header_t *h = (htp_header_t *)htp_table_get_c(tx1->response_headers, "Server");
    ASSERT_TRUE(h != NULL);
    ASSERT_TRUE(h->value != NULL);
    
    ASSERT_EQ(0, bstr_cmp_c(h->value, "Apache"));

    htp_tx_t *tx2 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 1);
    ASSERT_TRUE(tx2 != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx2->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx2->response_progress);

    ASSERT_TRUE(tx1 != tx2);
}

TEST_F(ConnectionParsing, ResponseFoldedHeaders) {
    int rc = test_run(home, "77-response-folded-headers.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx1 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx1 != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx1->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx1->response_progress);

    htp_header_t *h = (htp_header_t *)htp_table_get_c(tx1->response_headers, "Server");
    ASSERT_TRUE(h != NULL);
    ASSERT_TRUE(h->value != NULL);
    
    ASSERT_EQ(0, bstr_cmp_c(h->value, "Apache Server"));

    htp_tx_t *tx2 = (htp_tx_t *) htp_list_get(connp->conn->transactions, 1);
    ASSERT_TRUE(tx2 != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx2->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx2->response_progress);
}

TEST_F(ConnectionParsing, ResponseNoStatusHeaders) {
    int rc = test_run(home, "78-response-no-status-headers.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);
}

TEST_F(ConnectionParsing, ConnectInvalidHostport) {
    int rc = test_run(home, "79-connect-invalid-hostport.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(2, htp_list_size(connp->conn->transactions));
}

TEST_F(ConnectionParsing, HostnameInvalid1) {
    int rc = test_run(home, "80-hostname-invalid-1.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));   
}

TEST_F(ConnectionParsing, HostnameInvalid2) {
    int rc = test_run(home, "81-hostname-invalid-2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));
}

TEST_F(ConnectionParsing, Put) {
    int rc = test_run(home, "82-put.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));
    
    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);
    
    ASSERT_TRUE(tx->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_hostname, "www.example.com"));
}

TEST_F(ConnectionParsing, AuthDigestInvalidUsername2) {
    int rc = test_run(home, "83-auth-digest-invalid-username-2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);

    ASSERT_EQ(HTP_AUTH_DIGEST, tx->request_auth_type);

    ASSERT_TRUE(tx->request_auth_username == NULL);

    ASSERT_TRUE(tx->request_auth_password == NULL);

    ASSERT_TRUE(tx->flags & HTP_AUTH_INVALID);
}

TEST_F(ConnectionParsing, ResponseNoStatusHeaders2) {
    int rc = test_run(home, "84-response-no-status-headers-2.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);
}

/*
TEST_F(ConnectionParsing, ZeroByteRequestTimeout) {
    int rc = test_run(home, "85-zero-byte-request-timeout.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_NOT_STARTED, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);
}
*/

TEST_F(ConnectionParsing, PartialRequestTimeout) {
    int rc = test_run(home, "86-partial-request-timeout.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);
}

TEST_F(ConnectionParsing, IncorrectHostAmbiguousWarning) {
    int rc = test_run(home, "87-issue-55-incorrect-host-ambiguous-warning.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_TRUE(tx->parsed_uri_raw != NULL);

    ASSERT_TRUE(tx->parsed_uri_raw->port != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri_raw->port, "443"));

    ASSERT_TRUE(tx->parsed_uri_raw->hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri_raw->hostname, "www.example.com"));
    
    ASSERT_EQ(443, tx->parsed_uri_raw->port_number);

    ASSERT_TRUE(tx->request_hostname != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_hostname, "www.example.com"));
   
    ASSERT_FALSE(tx->flags & HTP_HOST_AMBIGUOUS);
}

TEST_F(ConnectionParsing, GetWhitespace) {
    int rc = test_run(home, "89-get-whitespace.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, " GET"));

    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/?p=%20"));

    ASSERT_TRUE(tx->parsed_uri != NULL);

    ASSERT_TRUE(tx->parsed_uri->query != NULL);

    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->query, "p=%20"));

    htp_param_t *p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p->value, " "));
}

TEST_F(ConnectionParsing, RequestUriTooLarge) {
    int rc = test_run(home, "90-request-uri-too-large.t", cfg, &connp);
    ASSERT_GE(rc, 0);

    ASSERT_EQ(1, htp_list_size(connp->conn->transactions));

    htp_tx_t *tx = (htp_tx_t *) htp_list_get(connp->conn->transactions, 0);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(HTP_REQUEST_COMPLETE, tx->request_progress);
    ASSERT_EQ(HTP_RESPONSE_COMPLETE, tx->response_progress);
}
