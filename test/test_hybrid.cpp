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

class HybridParsing_Get_User_Data {
    
public:
    
    // Request callback indicators.
    int callback_REQUEST_START_invoked;
    int callback_REQUEST_LINE_invoked;
    int callback_REQUEST_HEADERS_invoked;
    int callback_REQUEST_COMPLETE_invoked;

    // Response callback indicators.
    int callback_RESPONSE_START_invoked;
    int callback_RESPONSE_LINE_invoked;
    int callback_RESPONSE_HEADERS_invoked;
    int callback_RESPONSE_COMPLETE_invoked;

    // Transaction callback indicators.
    int callback_TRANSACTION_COMPLETE_invoked;

    // Response body handling fields.
    int response_body_chunks_seen;
    int response_body_correctly_received;

    HybridParsing_Get_User_Data() {
        Reset();
    }

    void Reset() {
        this->callback_REQUEST_START_invoked = 0;
        this->callback_REQUEST_LINE_invoked = 0;
        this->callback_REQUEST_HEADERS_invoked = 0;
        this->callback_REQUEST_COMPLETE_invoked = 0;
        this->callback_RESPONSE_START_invoked = 0;
        this->callback_RESPONSE_LINE_invoked = 0;
        this->callback_RESPONSE_HEADERS_invoked = 0;
        this->callback_RESPONSE_COMPLETE_invoked = 0;
        this->callback_TRANSACTION_COMPLETE_invoked = 0;
        this->response_body_chunks_seen = 0;
        this->response_body_correctly_received = 0;
    }
};

static int HybridParsing_Get_Callback_REQUEST_START(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_REQUEST_START_invoked;
    return HTP_OK;
}

static int HybridParsing_Get_Callback_REQUEST_LINE(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_REQUEST_LINE_invoked;
    return HTP_OK;
}

static int HybridParsing_Get_Callback_REQUEST_HEADERS(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_REQUEST_HEADERS_invoked;
    return HTP_OK;
}

static int HybridParsing_Get_Callback_REQUEST_COMPLETE(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_REQUEST_COMPLETE_invoked;
    return HTP_OK;
}

static int HybridParsing_Get_Callback_RESPONSE_START(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_RESPONSE_START_invoked;
    return HTP_OK;
}

static int HybridParsing_Get_Callback_RESPONSE_LINE(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_RESPONSE_LINE_invoked;
    return HTP_OK;
}

static int HybridParsing_Get_Callback_RESPONSE_HEADERS(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_RESPONSE_HEADERS_invoked;
    return HTP_OK;
}

static int HybridParsing_Get_Callback_RESPONSE_BODY_DATA(htp_tx_data_t *d) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(d->tx);

    // Don't do anything if in errored state.
    if (user_data->response_body_correctly_received == -1) return HTP_ERROR;

    switch (user_data->response_body_chunks_seen) {
        case 0:
            if ((d->len == 9) && (memcmp(d->data, "<h1>Hello", 9) == 0)) {
                user_data->response_body_chunks_seen++;
            } else {
                SCOPED_TRACE("Mismatch in 1st chunk");
                user_data->response_body_correctly_received = -1;
            }
            break;
        case 1:
            if ((d->len == 1) && (memcmp(d->data, " ", 1) == 0)) {
                user_data->response_body_chunks_seen++;
            } else {
                SCOPED_TRACE("Mismatch in 2nd chunk");
                user_data->response_body_correctly_received = -1;
            }
            break;
        case 2:
            if ((d->len == 11) && (memcmp(d->data, "World!</h1>", 11) == 0)) {
                user_data->response_body_chunks_seen++;
                user_data->response_body_correctly_received = 1;
            } else {
                SCOPED_TRACE("Mismatch in 3rd chunk");
                user_data->response_body_correctly_received = -1;
            }
            break;
        default:
            SCOPED_TRACE("Seen more than 3 chunks");
            user_data->response_body_correctly_received = -1;
            break;
    }

    return HTP_OK;
}

static int HybridParsing_Get_Callback_RESPONSE_COMPLETE(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_RESPONSE_COMPLETE_invoked;
    return HTP_OK;
}

static int HybridParsing_Get_Callback_TRANSACTION_COMPLETE(htp_tx_t *tx) {
    struct HybridParsing_Get_User_Data *user_data = (struct HybridParsing_Get_User_Data *) htp_tx_get_user_data(tx);
    ++user_data->callback_TRANSACTION_COMPLETE_invoked;
    return HTP_OK;
}

class HybridParsing : public testing::Test {
    
protected:

    virtual void SetUp() {
        testing::Test::SetUp();
        cfg = htp_config_create();
        htp_config_set_server_personality(cfg, HTP_SERVER_APACHE_2);
        htp_config_register_urlencoded_parser(cfg);
        htp_config_register_multipart_parser(cfg);

        connp = htp_connp_create(cfg);
        htp_connp_open(connp, "127.0.0.1", 32768, "127.0.0.1", 80, NULL);
        connp_open = true;
        user_data.Reset();
    }

    virtual void TearDown() {
        CloseConnParser( );
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        testing::Test::TearDown();
    }

    void CloseConnParser() {
        if (connp_open) {
            htp_connp_close(connp, NULL);
            connp_open = false;
        }
    }

    void RegisterUserCallbacks() {
        // Request callbacks
        htp_config_register_request_start(cfg, HybridParsing_Get_Callback_REQUEST_START);
        htp_config_register_request_line(cfg, HybridParsing_Get_Callback_REQUEST_LINE);
        htp_config_register_request_headers(cfg, HybridParsing_Get_Callback_REQUEST_HEADERS);
        htp_config_register_request_complete(cfg, HybridParsing_Get_Callback_REQUEST_COMPLETE);

        // Response callbacks
        htp_config_register_response_start(cfg, HybridParsing_Get_Callback_RESPONSE_START);
        htp_config_register_response_line(cfg, HybridParsing_Get_Callback_RESPONSE_LINE);
        htp_config_register_response_headers(cfg, HybridParsing_Get_Callback_RESPONSE_HEADERS);
        htp_config_register_response_body_data(cfg, HybridParsing_Get_Callback_RESPONSE_BODY_DATA);
        htp_config_register_response_complete(cfg, HybridParsing_Get_Callback_RESPONSE_COMPLETE);

        // Transaction calllbacks
        htp_config_register_transaction_complete(cfg, HybridParsing_Get_Callback_TRANSACTION_COMPLETE);
    }

    htp_connp_t *connp;
    htp_cfg_t   *cfg;
    bool         connp_open;

    // This must not be in a test stack frame as it will persist to TearDown
    // as htp user data.
    HybridParsing_Get_User_Data user_data;
};

/**
 * Test hybrid mode with one complete GET transaction; request then response
 * with a body. Most features are tested, including query string parameters and callbacks.
 */
TEST_F(HybridParsing, GetTest) {
    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Configure user data and callbacks
    htp_tx_set_user_data(tx, &user_data);

    // Register callbacks
    RegisterUserCallbacks();

    // Request begins
    htp_tx_state_request_start(tx);
    ASSERT_EQ(1, user_data.callback_REQUEST_START_invoked);

    // Request line data
    htp_tx_req_set_method(tx, "GET", 3, HTP_ALLOC_COPY);
    htp_tx_req_set_method_number(tx, HTP_M_GET);
    htp_tx_req_set_uri(tx, "/?p=1&q=2", 9, HTP_ALLOC_COPY);
    htp_tx_req_set_protocol(tx, "HTTP/1.1", 8, HTP_ALLOC_COPY);
    htp_tx_req_set_protocol_number(tx, HTP_PROTOCOL_1_1);
    htp_tx_req_set_protocol_0_9(tx, 0);

    // Request line complete
    htp_tx_state_request_line(tx);
    ASSERT_EQ(1, user_data.callback_REQUEST_LINE_invoked);

    // Check request line data
    ASSERT_TRUE(tx->request_method != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));
    ASSERT_TRUE(tx->request_uri != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/?p=1&q=2"));
    ASSERT_TRUE(tx->request_protocol != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_protocol, "HTTP/1.1"));

    ASSERT_TRUE(tx->parsed_uri != NULL);
    
    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/"));

    ASSERT_TRUE(tx->parsed_uri->query != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->query, "p=1&q=2"));

    // Check parameters
    htp_param_t *param_p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(param_p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_p->value, "1"));

    htp_param_t *param_q = htp_tx_req_get_param(tx, "q", 1);
    ASSERT_TRUE(param_q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_q->value, "2"));

    // Request headers
    htp_tx_req_set_header(tx, "Host", 4, "www.example.com", 15, HTP_ALLOC_COPY);
    htp_tx_req_set_header(tx, "Connection", 10, "keep-alive", 10, HTP_ALLOC_COPY);
    htp_tx_req_set_header(tx, "User-Agent", 10, "Mozilla/5.0", 11, HTP_ALLOC_COPY);

    // Request headers complete
    htp_tx_state_request_headers(tx);

    // Check headers
    ASSERT_EQ(1, user_data.callback_REQUEST_HEADERS_invoked);

    htp_header_t *h_host = (htp_header_t *) htp_table_get_c(tx->request_headers, "host");
    ASSERT_TRUE(h_host != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_host->value, "www.example.com"));

    htp_header_t *h_connection = (htp_header_t *) htp_table_get_c(tx->request_headers, "connection");
    ASSERT_TRUE(h_connection != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_connection->value, "keep-alive"));

    htp_header_t *h_ua = (htp_header_t *) htp_table_get_c(tx->request_headers, "user-agent");
    ASSERT_TRUE(h_ua != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_ua->value, "Mozilla/5.0"));

    // Request complete
    htp_tx_state_request_complete(tx);
    ASSERT_EQ(1, user_data.callback_REQUEST_COMPLETE_invoked);

    // Response begins
    htp_tx_state_response_start(tx);
    ASSERT_EQ(1, user_data.callback_RESPONSE_START_invoked);

    // Response line data
    htp_tx_res_set_status_line(tx, "HTTP/1.1 200 OK", 15, HTP_ALLOC_COPY);
    ASSERT_EQ(0, bstr_cmp_c(tx->response_protocol, "HTTP/1.1"));
    ASSERT_EQ(HTP_PROTOCOL_1_1, tx->response_protocol_number);
    ASSERT_EQ(200, tx->response_status_number);
    ASSERT_EQ(0, bstr_cmp_c(tx->response_message, "OK"));

    htp_tx_res_set_protocol_number(tx, HTP_PROTOCOL_1_0);
    ASSERT_EQ(HTP_PROTOCOL_1_0, tx->response_protocol_number);

    htp_tx_res_set_status_code(tx, 500);
    ASSERT_EQ(500, tx->response_status_number);

    htp_tx_res_set_status_message(tx, "Internal Server Error", 21, HTP_ALLOC_COPY);
    ASSERT_EQ(0, bstr_cmp_c(tx->response_message, "Internal Server Error"));

    // Response line complete
    htp_tx_state_response_line(tx);
    ASSERT_EQ(1, user_data.callback_RESPONSE_LINE_invoked);

    // Response header data
    htp_tx_res_set_header(tx, "Content-Type", 12, "text/html", 9, HTP_ALLOC_COPY);
    htp_tx_res_set_header(tx, "Server", 6, "Apache", 6, HTP_ALLOC_COPY);

    // Response headers complete
    htp_tx_state_response_headers(tx);
    ASSERT_EQ(1, user_data.callback_RESPONSE_HEADERS_invoked);

    // Check response headers
    htp_header_t *h_content_type = (htp_header_t *) htp_table_get_c(tx->response_headers, "content-type");
    ASSERT_TRUE(h_content_type != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_content_type->value, "text/html"));

    htp_header_t *h_server = (htp_header_t *) htp_table_get_c(tx->response_headers, "server");
    ASSERT_TRUE(h_server != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_server->value, "Apache"));

    // Response body data
    htp_tx_res_process_body_data(tx, "<h1>Hello", 9);
    htp_tx_res_process_body_data(tx, " ", 1);
    htp_tx_res_process_body_data(tx, "World!</h1>", 11);
    ASSERT_EQ(1, user_data.response_body_correctly_received);

    // Check that the API is rejecting NULL data.
    ASSERT_EQ(HTP_ERROR, htp_tx_res_process_body_data(tx, NULL, 1));

    // Trailing response headers
    htp_tx_res_set_headers_clear(tx);
    ASSERT_EQ(0, htp_table_size(tx->response_headers));

    htp_tx_res_set_header(tx, "Content-Type", 12, "text/html", 9, HTP_ALLOC_COPY);
    htp_tx_res_set_header(tx, "Server", 6, "Apache", 6, HTP_ALLOC_COPY);

    // Check trailing response headers
    h_content_type = (htp_header_t *) htp_table_get_c(tx->response_headers, "content-type");
    ASSERT_TRUE(h_content_type != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_content_type->value, "text/html"));

    h_server = (htp_header_t *) htp_table_get_c(tx->response_headers, "server");
    ASSERT_TRUE(h_server != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_server->value, "Apache"));

    htp_tx_state_response_complete(tx);
    ASSERT_EQ(1, user_data.callback_RESPONSE_COMPLETE_invoked);
}

/**
 * Use a POST request in order to test request body processing and parameter parsing.
 */
TEST_F(HybridParsing, PostUrlecodedTest) {
    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Request begins
    htp_tx_state_request_start(tx);

    // Request line data
    htp_tx_req_set_method(tx, "POST", 4, HTP_ALLOC_COPY);
    htp_tx_req_set_method_number(tx, HTP_M_GET);
    htp_tx_req_set_uri(tx, "/", 1, HTP_ALLOC_COPY);
    htp_tx_req_set_protocol(tx, "HTTP/1.1", 8, HTP_ALLOC_COPY);
    htp_tx_req_set_protocol_number(tx, HTP_PROTOCOL_1_1);
    htp_tx_req_set_protocol_0_9(tx, 0);

    // Request line complete
    htp_tx_state_request_line(tx);

    // Configure headers to trigger the URLENCODED parser
    htp_tx_req_set_header(tx, "Content-Type", 12, HTP_URLENCODED_MIME_TYPE,
            strlen(HTP_URLENCODED_MIME_TYPE), HTP_ALLOC_COPY);
    htp_tx_req_set_header(tx, "Content-Length", 14, "7", 1, HTP_ALLOC_COPY);

    // Request headers complete
    htp_tx_state_request_headers(tx);

    // Send request body
    htp_tx_req_process_body_data(tx, "p=1", 3);
    htp_tx_req_process_body_data(tx, NULL, 0);
    htp_tx_req_process_body_data(tx, "&", 1);
    htp_tx_req_process_body_data(tx, "q=2", 3);

    // Check that the API is rejecting NULL data.
    ASSERT_EQ(HTP_ERROR, htp_tx_req_process_body_data(tx, NULL, 1));

    // Trailing request headers
    htp_tx_req_set_headers_clear(tx);
    ASSERT_EQ(0, htp_table_size(tx->request_headers));

    htp_tx_req_set_header(tx, "Host", 4, "www.example.com", 15, HTP_ALLOC_COPY);
    htp_tx_req_set_header(tx, "Connection", 10, "keep-alive", 10, HTP_ALLOC_COPY);
    htp_tx_req_set_header(tx, "User-Agent", 10, "Mozilla/5.0", 11, HTP_ALLOC_COPY);

    htp_header_t *h_host = (htp_header_t *) htp_table_get_c(tx->request_headers, "host");
    ASSERT_TRUE(h_host != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_host->value, "www.example.com"));

    htp_header_t *h_connection = (htp_header_t *) htp_table_get_c(tx->request_headers, "connection");
    ASSERT_TRUE(h_connection != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_connection->value, "keep-alive"));

    htp_header_t *h_ua = (htp_header_t *) htp_table_get_c(tx->request_headers, "user-agent");
    ASSERT_TRUE(h_ua != NULL);
    ASSERT_EQ(0, bstr_cmp_c(h_ua->value, "Mozilla/5.0"));

    // Request complete
    htp_tx_state_request_complete(tx);

    // Check parameters

    htp_param_t *param_p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(param_p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_p->value, "1"));

    htp_param_t *param_q = htp_tx_req_get_param(tx, "q", 1);
    ASSERT_TRUE(param_q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_q->value, "2"));
}

static char HybridParsing_CompressedResponse[] =
        "H4sIAAAAAAAAAG2PwQ6CMBBE73xFU++tXk2pASliAiEhPegRYUOJYEktEP5eqB6dy2ZnJ5O3LJFZ"
        "yj2WiCBah7zKVPBMT1AjCf2gTWnabmH0e/AY/QXDPLqj8HLO07zw8S52wkiKm1zXvRPeeg//2lbX"
        "kwpQrauxh5dFqnyj3uVYgJJCxD5W1g5HSud5Jo3WTQek0mR8UgNlDYZOLcz0ZMuH3y+YKzDAaMDJ"
        "SrihOVL32QceVXUy4QAAAA==";

static void HybridParsing_CompressedResponse_Setup(htp_tx_t *tx) {
    htp_tx_state_request_start(tx);

    htp_tx_req_set_method(tx, "GET", 3, HTP_ALLOC_REUSE);
    htp_tx_req_set_method_number(tx, HTP_M_GET);
    htp_tx_req_set_uri(tx, "/", 1, HTP_ALLOC_COPY);    
    htp_tx_req_set_protocol(tx, "HTTP/1.1", 8, HTP_ALLOC_REUSE);
    htp_tx_req_set_protocol_number(tx, HTP_PROTOCOL_1_1);
    htp_tx_req_set_protocol_0_9(tx, 0);

    htp_tx_state_request_line(tx);
    htp_tx_state_request_headers(tx);
    htp_tx_state_request_complete(tx);

    htp_tx_state_response_start(tx);

    htp_tx_res_set_status_line(tx, "HTTP/1.1 200 OK", 15, HTP_ALLOC_REUSE);
    htp_tx_res_set_header(tx, "Content-Encoding", 16, "gzip", 4, HTP_ALLOC_REUSE);
    htp_tx_res_set_header(tx, "Content-Length", 14, "187", 3, HTP_ALLOC_REUSE);

    htp_tx_state_response_headers(tx);

    bstr *body = htp_base64_decode_mem(HybridParsing_CompressedResponse, strlen(HybridParsing_CompressedResponse));
    ASSERT_TRUE(body != NULL);

    htp_tx_res_process_body_data(tx, bstr_ptr(body), bstr_len(body));
    bstr_free(body);

    htp_tx_state_response_complete(tx);
}

/**
 * Test with a compressed response body and decompression enabled.
 */
TEST_F(HybridParsing, CompressedResponse) {
    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    HybridParsing_CompressedResponse_Setup(tx);

    ASSERT_EQ(187, tx->response_message_len);
    ASSERT_EQ(225, tx->response_entity_len);
}

/**
 * Test with a compressed response body and decompression disabled.
 */
TEST_F(HybridParsing, CompressedResponseNoDecompression) {
    // Disable decompression
    htp_config_set_response_decompression(cfg, 0);

    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    HybridParsing_CompressedResponse_Setup(tx);

    ASSERT_EQ(187, tx->response_message_len);
    ASSERT_EQ(187, tx->response_entity_len);
}

static int HybridParsing_ForcedDecompressionTest_Callback_RESPONSE_HEADERS(htp_tx_t *tx) {
    tx->response_content_encoding_processing = HTP_COMPRESSION_GZIP;
    return HTP_OK;
}

/**
 * Test forced decompression.
 */
TEST_F(HybridParsing, ForcedDecompression) {
    // Disable decompression
    htp_config_set_response_decompression(cfg, 0);

    // Register a callback that will force decompression
    htp_config_register_response_headers(cfg, HybridParsing_ForcedDecompressionTest_Callback_RESPONSE_HEADERS);

    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    HybridParsing_CompressedResponse_Setup(tx);

    ASSERT_EQ(187, tx->response_message_len);
    ASSERT_EQ(225, tx->response_entity_len);
}

static int HybridParsing_DisableDecompressionTest_Callback_RESPONSE_HEADERS(htp_tx_t *tx) {
    tx->response_content_encoding_processing = HTP_COMPRESSION_NONE;
    return HTP_OK;
}

/**
 * Test disabling decompression from a callback.
 */
TEST_F(HybridParsing, DisableDecompression) {
    // Disable decompression
    htp_config_set_response_decompression(cfg, 0);

    // Register a callback that will force decompression
    htp_config_register_response_headers(cfg, HybridParsing_DisableDecompressionTest_Callback_RESPONSE_HEADERS);

    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    HybridParsing_CompressedResponse_Setup(tx);

    ASSERT_EQ(187, tx->response_message_len);
    ASSERT_EQ(187, tx->response_entity_len);
}

TEST_F(HybridParsing, ParamCaseSensitivity) {
    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Request begins
    htp_tx_state_request_start(tx);

    // Request line data
    htp_tx_req_set_method(tx, "GET", 3, HTP_ALLOC_COPY);
    htp_tx_req_set_method_number(tx, HTP_M_GET);
    htp_tx_req_set_uri(tx, "/?p=1&Q=2", 9, HTP_ALLOC_COPY);
    htp_tx_req_set_protocol(tx, "HTTP/1.1", 8, HTP_ALLOC_COPY);
    htp_tx_req_set_protocol_number(tx, HTP_PROTOCOL_1_1);
    htp_tx_req_set_protocol_0_9(tx, 0);

    // Request line complete
    htp_tx_state_request_line(tx);

    // Check the parameters.

    htp_param_t *param_p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(param_p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_p->value, "1"));

    param_p = htp_tx_req_get_param(tx, "P", 1);
    ASSERT_TRUE(param_p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_p->value, "1"));

    htp_param_t *param_q = htp_tx_req_get_param(tx, "q", 1);
    ASSERT_TRUE(param_q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_q->value, "2"));

    param_q = htp_tx_req_get_param_ex(tx, HTP_SOURCE_QUERY_STRING, "q", 1);
    ASSERT_TRUE(param_q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_q->value, "2"));

    param_q = htp_tx_req_get_param_ex(tx, HTP_SOURCE_QUERY_STRING, "Q", 1);
    ASSERT_TRUE(param_q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_q->value, "2"));
}

/**
 * Use a POST request in order to test request body processing and parameter
 * parsing. In hybrid mode, we expect that the body arrives to us dechunked.
 */
TEST_F(HybridParsing, PostUrlecodedChunked) {
    // Create a new LibHTP transaction.
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Request begins.
    htp_tx_state_request_start(tx);

    // Request line data.
    htp_tx_req_set_method(tx, "POST", 4, HTP_ALLOC_COPY);
    htp_tx_req_set_method_number(tx, HTP_M_GET);
    htp_tx_req_set_uri(tx, "/", 1, HTP_ALLOC_COPY);
    htp_tx_req_set_protocol(tx, "HTTP/1.1", 8, HTP_ALLOC_COPY);
    htp_tx_req_set_protocol_number(tx, HTP_PROTOCOL_1_1);
    htp_tx_req_set_protocol_0_9(tx, 0);
    htp_tx_state_request_line(tx);

    // Configure headers to trigger the URLENCODED parser.
    htp_tx_req_set_header(tx, "Content-Type", 12, HTP_URLENCODED_MIME_TYPE,
            strlen(HTP_URLENCODED_MIME_TYPE), HTP_ALLOC_COPY);
    htp_tx_req_set_header(tx, "Transfer-Encoding", 17, "chunked", 7, HTP_ALLOC_COPY);

    // Request headers complete.
    htp_tx_state_request_headers(tx);

    // Send request body.
    htp_tx_req_process_body_data(tx, "p=1", 3);
    htp_tx_req_process_body_data(tx, "&", 1);
    htp_tx_req_process_body_data(tx, "q=2", 3);

    // Request complete.
    htp_tx_state_request_complete(tx);

    // Check the parameters.

    htp_param_t *param_p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(param_p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_p->value, "1"));

    htp_param_t *param_q = htp_tx_req_get_param(tx, "q", 1);
    ASSERT_TRUE(param_q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_q->value, "2"));
}

TEST_F(HybridParsing, RequestLineParsing1) {
    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Request begins
    htp_tx_state_request_start(tx);

    // Request line data
    htp_tx_req_set_line(tx, "GET /?p=1&q=2 HTTP/1.0", 22, HTP_ALLOC_COPY);

    // Request line complete
    htp_tx_state_request_line(tx);   

    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));    
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/?p=1&q=2"));
    ASSERT_EQ(0, bstr_cmp_c(tx->request_protocol, "HTTP/1.0"));

    ASSERT_TRUE(tx->parsed_uri != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->query, "p=1&q=2"));

    // Check parameters
    htp_param_t *param_p = htp_tx_req_get_param(tx, "p", 1);
    ASSERT_TRUE(param_p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_p->value, "1"));

    htp_param_t *param_q = htp_tx_req_get_param(tx, "q", 1);
    ASSERT_TRUE(param_q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(param_q->value, "2"));
}

TEST_F(HybridParsing, RequestLineParsing2) {
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Feed data to the parser.

    htp_tx_state_request_start(tx);
    htp_tx_req_set_line(tx, "GET /", 5, HTP_ALLOC_COPY);
    htp_tx_state_request_line(tx);

    // Check the results now.

    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));
    ASSERT_EQ(1, tx->is_protocol_0_9);
    ASSERT_EQ(HTP_PROTOCOL_0_9, tx->request_protocol_number);
    ASSERT_TRUE(tx->request_protocol == NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/"));
}

TEST_F(HybridParsing, ParsedUriSupplied) {
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Feed data to the parser.

    htp_tx_state_request_start(tx);
    htp_tx_req_set_line(tx, "GET /?p=1&q=2 HTTP/1.0", 22, HTP_ALLOC_COPY);

    htp_uri_t *u = htp_uri_alloc();
    u->path = bstr_dup_c("/123");
    htp_tx_req_set_parsed_uri(tx, u);

    htp_tx_state_request_line(tx);

    // Check the results now.

    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));
    ASSERT_TRUE(tx->request_protocol != NULL);
    ASSERT_EQ(HTP_PROTOCOL_1_0, tx->request_protocol_number);
    ASSERT_TRUE(tx->request_uri != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/?p=1&q=2"));

    ASSERT_TRUE(tx->parsed_uri != NULL);
    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/123"));
}


class HybridParsingNoOpen : public testing::Test {
protected:

    virtual void SetUp() {
        cfg = htp_config_create();
        htp_config_set_server_personality(cfg, HTP_SERVER_GENERIC);
    }

    virtual void TearDown() {
        htp_config_destroy(cfg);
    }

    htp_cfg_t *cfg;

    // This must not be in a test stack frame as it will persist to TearDown
    // as htp user data.
    HybridParsing_Get_User_Data user_data;
};

/**
 * Test hybrid mode with one complete GET transaction; request then response
 * with no body. Used to crash in htp_connp_close().
 */
TEST_F(HybridParsing, TestRepeatCallbacks)
{
    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Configure user data and callbacks
    htp_tx_set_user_data(tx, &user_data);

    // Request callbacks
    RegisterUserCallbacks();

    // Request begins
    htp_tx_state_request_start(tx);
    ASSERT_EQ(1, user_data.callback_REQUEST_START_invoked);

    // Request line data
    htp_tx_req_set_line(tx, "GET / HTTP/1.0", 14, HTP_ALLOC_COPY);

    // Request line complete
    htp_tx_state_request_line(tx);
    ASSERT_EQ(1, user_data.callback_REQUEST_LINE_invoked);

    // Check request line data
    ASSERT_TRUE(tx->request_method != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_method, "GET"));
    ASSERT_TRUE(tx->request_uri != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_uri, "/"));
    ASSERT_TRUE(tx->request_protocol != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->request_protocol, "HTTP/1.0"));

    ASSERT_TRUE(tx->parsed_uri != NULL);
    
    ASSERT_TRUE(tx->parsed_uri->path != NULL);
    ASSERT_EQ(0, bstr_cmp_c(tx->parsed_uri->path, "/"));

    // Request headers complete    
    htp_tx_state_request_headers(tx);
    ASSERT_EQ(1, user_data.callback_REQUEST_HEADERS_invoked);

    // Request complete
    htp_tx_state_request_complete(tx);
    ASSERT_EQ(1, user_data.callback_REQUEST_COMPLETE_invoked);

    // Response begins
    htp_tx_state_response_start(tx);
    ASSERT_EQ(1, user_data.callback_RESPONSE_START_invoked);

    // Response line data
    htp_tx_res_set_status_line(tx, "HTTP/1.1 200 OK\r\n", 17, HTP_ALLOC_COPY);

    // Response line complete
    htp_tx_state_response_line(tx);
    ASSERT_EQ(1, user_data.callback_RESPONSE_LINE_invoked);
    
    // Response headers complete
    htp_tx_state_response_headers(tx);
    ASSERT_EQ(1, user_data.callback_RESPONSE_HEADERS_invoked);
    
    // Response complete
    htp_tx_state_response_complete(tx);
    ASSERT_EQ(1, user_data.callback_RESPONSE_COMPLETE_invoked);

    ASSERT_EQ(htp_tx_destroy(tx), HTP_OK);

    // Close connection
    CloseConnParser();

    ASSERT_EQ(1, user_data.callback_REQUEST_START_invoked);
    ASSERT_EQ(1, user_data.callback_REQUEST_LINE_invoked);
    ASSERT_EQ(1, user_data.callback_REQUEST_HEADERS_invoked);
    ASSERT_EQ(1, user_data.callback_REQUEST_COMPLETE_invoked);
    ASSERT_EQ(1, user_data.callback_RESPONSE_START_invoked);
    ASSERT_EQ(1, user_data.callback_RESPONSE_LINE_invoked);
    ASSERT_EQ(1, user_data.callback_RESPONSE_HEADERS_invoked);
    ASSERT_EQ(1, user_data.callback_RESPONSE_COMPLETE_invoked);
    ASSERT_EQ(1, user_data.callback_TRANSACTION_COMPLETE_invoked);
}

/**
 * Try to delete a transaction before it is complete.
 */
TEST_F(HybridParsing, DeleteTransactionBeforeComplete)
{
    // Create a new LibHTP transaction
    htp_tx_t *tx = htp_connp_tx_create(connp);
    ASSERT_TRUE(tx != NULL);

    // Request begins
    htp_tx_state_request_start(tx);

    // Request line data
    htp_tx_req_set_line(tx, "GET / HTTP/1.0", 14, HTP_ALLOC_COPY);

    ASSERT_EQ(htp_tx_destroy(tx), HTP_ERROR);

    // Close connection
    CloseConnParser();   
}
