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

#include "htp_private.h"

static bstr *copy_or_wrap_mem(const void *data, size_t len, enum htp_alloc_strategy_t alloc) {
    if (alloc == HTP_ALLOC_REUSE) {
        return bstr_wrap_mem(data, len);
    } else {
        return bstr_dup_mem(data, len);
    }
}

htp_tx_t *htp_tx_create(htp_connp_t *connp) {
    htp_tx_t *tx = calloc(1, sizeof (htp_tx_t));
    if (tx == NULL) return NULL;

    tx->connp = connp;
    tx->conn = connp->conn;
    tx->cfg = connp->cfg;
    tx->is_config_shared = HTP_CONFIG_SHARED;

    tx->request_protocol_number = HTP_PROTOCOL_UNKNOWN;
    tx->request_headers = htp_table_create(32);
    tx->request_params = htp_table_create(32);
    tx->request_content_length = -1;

    tx->parsed_uri_raw = htp_uri_alloc();

    tx->response_status = NULL;
    tx->response_status_number = HTP_STATUS_UNKNOWN;
    tx->response_protocol_number = HTP_PROTOCOL_UNKNOWN;

    tx->response_headers = htp_table_create(32);
    tx->response_content_length = -1;

    return tx;
}

void htp_tx_destroy(htp_tx_t *tx) {
    // Request.

    bstr_free(tx->request_line);

    bstr_free(tx->request_method);
    bstr_free(tx->request_uri);
    bstr_free(tx->request_protocol);

    htp_uri_free(tx->parsed_uri_raw);
    htp_uri_free(tx->parsed_uri);

    // Destroy request_headers.
    if (tx->request_headers != NULL) {
        htp_header_t *h = NULL;
        for (size_t i = 0, n = htp_table_size(tx->request_headers); i < n; i++) {
            h = htp_table_get_index(tx->request_headers, i, NULL);
            bstr_free(h->name);
            bstr_free(h->value);
            free(h);
        }

        htp_table_destroy(tx->request_headers);
    }

    bstr_free(tx->request_content_type);

    if (tx->request_hostname != NULL) {
        bstr_free(tx->request_hostname);
    }

    // Response.

    bstr_free(tx->response_line);

    bstr_free(tx->response_protocol);
    bstr_free(tx->response_status);
    bstr_free(tx->response_message);

    // Destroy response headers.
    if (tx->response_headers != NULL) {
        htp_header_t *h = NULL;
        for (size_t i = 0, n = htp_table_size(tx->response_headers); i < n; i++) {
            h = htp_table_get_index(tx->response_headers, i, NULL);
            bstr_free(h->name);
            bstr_free(h->value);
            free(h);
        }

        htp_table_destroy(tx->response_headers);
    }

    // Tell the connection to remove this transaction from the list.
    htp_conn_remove_tx(tx->conn, tx);

    // Invalidate the pointer to this transactions held
    // by the connection parser. This is to allow a transaction
    // to be destroyed from within the final response callback.
    if (tx->connp != NULL) {
        if (tx->connp->out_tx == tx) {
            tx->connp->out_tx = NULL;
        }
    }


    bstr_free(tx->response_content_type);

    // Parsers

    htp_urlenp_destroy(tx->request_urlenp_query);
    htp_urlenp_destroy(tx->request_urlenp_body);
    htp_mpartp_destroy(tx->request_mpartp);

    // Request parameters

    htp_param_t *param = NULL;
    for (size_t i = 0, n = htp_table_size(tx->request_params); i < n; i++) {
        param = htp_table_get_index(tx->request_params, i, NULL);
        free(param->name);
        free(param->value);
        free(param);
    }

    htp_table_destroy(tx->request_params);

    // Request cookies

    if (tx->request_cookies != NULL) {
        bstr *b = NULL;
        for (size_t i = 0, n = htp_table_size(tx->request_cookies); i < n; i++) {
            b = htp_table_get_index(tx->request_cookies, i, NULL);
            bstr_free(b);
        }

        htp_table_destroy(tx->request_cookies);
    }

    htp_hook_destroy(tx->hook_request_body_data);

    // If we're using a private configuration, destroy it.
    if (tx->is_config_shared == HTP_CONFIG_PRIVATE) {
        htp_config_destroy(tx->cfg);
    }

    free(tx);
}

int htp_tx_get_is_config_shared(const htp_tx_t *tx) {
    return tx->is_config_shared;
}

void *htp_tx_get_user_data(const htp_tx_t *tx) {
    return tx->user_data;
}

void htp_tx_set_config(htp_tx_t *tx, htp_cfg_t *cfg, int is_cfg_shared) {
    if ((is_cfg_shared != HTP_CONFIG_PRIVATE) && (is_cfg_shared != HTP_CONFIG_SHARED)) return;

    // If we're using a private configuration, destroy it.
    if (tx->is_config_shared == HTP_CONFIG_PRIVATE) {
        htp_config_destroy(tx->cfg);
    }

    tx->cfg = cfg;
    tx->is_config_shared = is_cfg_shared;
}

void htp_tx_set_user_data(htp_tx_t *tx, void *user_data) {
    tx->user_data = user_data;
}

htp_status_t htp_tx_req_add_param(htp_tx_t *tx, htp_param_t *param) {
    if (tx->cfg->parameter_processor != NULL) {
        if (tx->cfg->parameter_processor(param) != HTP_OK) return HTP_ERROR;
    }

    return htp_table_addk(tx->request_params, param->name, param);
}

htp_param_t *htp_tx_req_get_param(htp_tx_t *tx, const char *name, size_t name_len) {
    return htp_table_get_mem(tx->request_params, name, name_len);
}

htp_param_t *htp_tx_req_get_param_ex(htp_tx_t *tx, enum htp_data_source_t source, const char *name, size_t name_len) {
    htp_param_t *p = NULL;

    for (int i = 0, n = htp_table_size(tx->request_params); i < n; i++) {
        p = htp_table_get_index(tx->request_params, i, NULL);
        if (p->source != source) continue;

        if (bstr_cmp_mem_nocase(p->name, name, name_len) == 0) return p;
    }

    return NULL;
}

int htp_tx_req_has_body(const htp_tx_t *tx) {
    if ((tx->request_transfer_coding == HTP_CODING_IDENTITY) || (tx->request_transfer_coding == HTP_CODING_CHUNKED)) {
        return 1;
    }

    return 0;
}

htp_status_t htp_tx_req_set_header(htp_tx_t *tx, const char *name, size_t name_len,
        const char *value, size_t value_len, enum htp_alloc_strategy_t alloc) {
    if ((name == NULL) || (value == NULL)) return HTP_ERROR;

    htp_header_t *h = calloc(1, sizeof (htp_header_t));
    if (h == NULL) return HTP_ERROR;

    h->name = copy_or_wrap_mem(name, name_len, alloc);
    if (h->name == NULL) {
        free(h);
        return HTP_ERROR;
    }

    h->value = copy_or_wrap_mem(value, value_len, alloc);
    if (h->value == NULL) {
        bstr_free(h->name);
        free(h);
        return HTP_ERROR;
    }

    if (htp_table_add(tx->request_headers, h->name, h) != HTP_OK) {
        bstr_free(h->name);
        bstr_free(h->value);
        free(h);
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_req_set_method(htp_tx_t *tx, const char *method, size_t method_len, enum htp_alloc_strategy_t alloc) {
    if (method == NULL) return HTP_ERROR;

    tx->request_method = copy_or_wrap_mem(method, method_len, alloc);
    if (tx->request_method == NULL) return HTP_ERROR;

    return HTP_OK;
}

void htp_tx_req_set_method_number(htp_tx_t *tx, enum htp_method_t method_number) {
    tx->request_method_number = method_number;
}

htp_status_t htp_tx_req_set_uri(htp_tx_t *tx, const char *uri, size_t uri_len, enum htp_alloc_strategy_t alloc) {
    if (uri == NULL) return HTP_ERROR;

    tx->request_uri = copy_or_wrap_mem(uri, uri_len, alloc);
    if (tx->request_uri == NULL) return HTP_ERROR;

    return HTP_OK;
}

htp_status_t htp_tx_req_set_protocol(htp_tx_t *tx, const char *protocol, size_t protocol_len, enum htp_alloc_strategy_t alloc) {
    if (protocol == NULL) return HTP_ERROR;

    tx->request_protocol = copy_or_wrap_mem(protocol, protocol_len, alloc);
    if (tx->request_protocol == NULL) return HTP_ERROR;

    return HTP_OK;
}

void htp_tx_req_set_protocol_number(htp_tx_t *tx, int protocol_number) {
    tx->request_protocol_number = protocol_number;
}

void htp_tx_req_set_protocol_0_9(htp_tx_t *tx, int is_protocol_0_9) {
    if (is_protocol_0_9) {
        tx->is_protocol_0_9 = 1;
    } else {
        tx->is_protocol_0_9 = 0;
    }
}

static htp_status_t htp_tx_process_request_headers(htp_tx_t *tx) {
    // Determine if we have a request body, and how it is packaged.
    htp_header_t *cl = htp_table_get_c(tx->request_headers, "content-length");
    htp_header_t *te = htp_table_get_c(tx->request_headers, "transfer-encoding");

    // Check for the Transfer-Encoding header, which would indicate a chunked request body.
    if (te != NULL) {
        // Make sure it contains "chunked" only.
        if (bstr_cmp_c(te->value, "chunked") != 0) {
            // Invalid T-E header value.
            tx->flags |= HTP_INVALID_CHUNKING;

            htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                    "Invalid T-E value in request");
        }

        // Chunked encoding is a HTTP/1.1 feature. Check that some other protocol is not
        // used. The flag will also be set if the protocol could not be parsed.
        //
        // TODO IIS 7.0, for example, would ignore the T-E header when it
        //      it is used with a protocol below HTTP 1.1.
        if (tx->request_protocol_number < HTP_PROTOCOL_1_1) {
            tx->flags |= HTP_INVALID_CHUNKING;
        }

        // If the T-E header is present we are going to use it.
        tx->request_transfer_coding = HTP_CODING_CHUNKED;

        // We are still going to check for the presence of C-L.
        if (cl != NULL) {
            // This is a violation of the RFC.
            tx->flags |= HTP_REQUEST_SMUGGLING;
        }
    } else if (cl != NULL) {
        // We have a request body of known length.
        tx->request_transfer_coding = HTP_CODING_IDENTITY;

        // Check for a folded C-L header.
        if (cl->flags & HTP_FIELD_FOLDED) {
            tx->flags |= HTP_REQUEST_SMUGGLING;
        }

        // Check for multiple C-L headers.
        if (cl->flags & HTP_FIELD_REPEATED) {
            tx->flags |= HTP_REQUEST_SMUGGLING;
        }

        // Get body length.
        tx->request_content_length = htp_parse_content_length(cl->value);
        if (tx->request_content_length < 0) {
            htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Invalid C-L field in request");
            return HTP_ERROR;
        }
    } else {
        // No body.
        tx->request_transfer_coding = HTP_CODING_NO_BODY;
    }

    // Check for PUT requests, which we need to treat as file uploads.
    if (tx->request_method_number == HTP_M_PUT) {
        if (htp_tx_req_has_body(tx)) {
            // Prepare to treat PUT request body as a file.
            tx->connp->put_file = calloc(1, sizeof (htp_file_t));
            if (tx->connp->put_file == NULL) return HTP_ERROR;
            tx->connp->put_file->source = HTP_FILE_PUT;
        } else {
            // TODO Warn about PUT request without a body.
        }

        return HTP_OK;
    }

    // Use the hostname from the URI, when available.   

    if (tx->parsed_uri->hostname != NULL) {
        tx->request_hostname = bstr_dup(tx->parsed_uri->hostname);
    }

    tx->request_port_number = tx->parsed_uri->port_number;

    // Examine the Host header.

    htp_header_t *h = htp_table_get_c(tx->request_headers, "host");
    if (h == NULL) {
        // No host information in the headers.

        // HTTP/1.1 requires host information in the headers.
        if (tx->request_protocol_number >= HTP_PROTOCOL_1_1) {
            tx->flags |= HTP_HOST_MISSING;
            htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                    "Host information in request headers required by HTTP/1.1");
        }
    } else {
        // Host information available in the headers.

        bstr *hostname;
        int port;

        if (htp_parse_header_hostport(h->value, &hostname, &port, &(tx->flags)) != HTP_OK) return HTP_ERROR;

        // Is there host information in the URI?
        if (tx->request_hostname == NULL) {
            // There is no host information in the URI. Place the
            // hostname from the headers into the parsed_uri structure.
            tx->request_hostname = hostname;
            tx->request_port_number = port;
        } else {
            if ((bstr_cmp_nocase(hostname, tx->request_hostname) != 0) || (port != tx->request_port_number)) {
                // The host information is different in the headers and the URI. The
                // HTTP RFC states that we should ignore the header copy.
                tx->flags |= HTP_HOST_AMBIGUOUS;
                htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Host information ambiguous");
            }

            bstr_free(hostname);
        }
    }

    // Parse the Content-Type header.
    htp_header_t *ct = htp_table_get_c(tx->request_headers, "content-type");
    if (ct != NULL) {
        if (htp_parse_ct_header(ct->value, &tx->request_content_type) != HTP_OK) return HTP_ERROR;
    }

    // Parse cookies.
    if (tx->connp->cfg->parse_request_cookies) {
        htp_parse_cookies_v0(tx->connp);
    }

    // Parse authentication information.
    if (tx->connp->cfg->parse_request_auth) {
        htp_parse_authorization(tx->connp);
    }

    // Finalize sending raw header data.
    htp_status_t rc = htp_connp_req_receiver_finalize_clear(tx->connp);
    if (rc != HTP_OK) return rc;

    // Run hook REQUEST_HEADERS.
    rc = htp_hook_run_all(tx->connp->cfg->hook_request_headers, tx->connp);
    if (rc != HTP_OK) return rc;

    return HTP_OK;
}

htp_status_t htp_tx_req_process_body_data(htp_tx_t *tx, const void *data, size_t len) {
    // Keep track of the body length.
    tx->request_entity_len += len;

    // Send data to the callbacks.

    htp_tx_data_t d;
    d.tx = tx;
    d.data = (unsigned char *) data;
    d.len = len;

    int rc = htp_req_run_hook_body_data(tx->connp, &d);
    if (rc != HTP_OK) {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                "Request body data callback returned error (%d)", rc);
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_req_set_headers_clear(htp_tx_t *tx) {
    if (tx->request_headers == NULL) return HTP_ERROR;

    htp_header_t *h = NULL;
    for (int i = 0, n = htp_table_size(tx->request_headers); i < n; i++) {
        h = htp_table_get_index(tx->request_headers, i, NULL);
        bstr_free(h->name);
        bstr_free(h->value);
        free(h);
    }

    htp_table_destroy(tx->request_headers);

    tx->request_headers = htp_table_create(32);
    if (tx->request_headers == NULL) return HTP_ERROR;

    return HTP_OK;
}

htp_status_t htp_tx_req_set_line(htp_tx_t *tx, const char *line, size_t line_len, enum htp_alloc_strategy_t alloc) {
    if ((line == NULL) || (line_len == 0)) return HTP_ERROR;

    tx->request_line = copy_or_wrap_mem(line, line_len, alloc);
    if (tx->request_line == NULL) return HTP_ERROR;

    if (tx->connp->cfg->parse_request_line(tx->connp) != HTP_OK) return HTP_ERROR;

    return HTP_OK;
}

void htp_tx_req_set_parsed_uri(htp_tx_t *tx, htp_uri_t *parsed_uri) {
    if (tx->parsed_uri != NULL) {
        htp_uri_free(tx->parsed_uri);
    }

    tx->parsed_uri = parsed_uri;
}

htp_status_t htp_tx_res_set_status_line(htp_tx_t *tx, const char *line, size_t line_len, enum htp_alloc_strategy_t alloc) {
    if ((line == NULL) || (line_len == 0)) return HTP_ERROR;

    tx->response_line = copy_or_wrap_mem(line, line_len, alloc);
    if (tx->response_line == NULL) return HTP_ERROR;

    if (tx->connp->cfg->parse_response_line(tx->connp) != HTP_OK) return HTP_ERROR;

    return HTP_OK;
}

void htp_tx_res_set_protocol_number(htp_tx_t *tx, int protocol_number) {
    tx->response_protocol_number = protocol_number;
}

void htp_tx_res_set_status_code(htp_tx_t *tx, int status_code) {
    tx->response_status_number = status_code;
}

htp_status_t htp_tx_res_set_status_message(htp_tx_t *tx, const char *msg, size_t msg_len, enum htp_alloc_strategy_t alloc) {
    if (msg == NULL) return HTP_ERROR;

    if (tx->response_message != NULL) {
        bstr_free(tx->response_message);
    }

    tx->response_message = copy_or_wrap_mem(msg, msg_len, alloc);
    if (tx->response_message == NULL) return HTP_ERROR;

    return HTP_OK;
}

htp_status_t htp_tx_state_response_line(htp_tx_t *tx) {
    #if 0
    // Commented-out until we determine which fields can be
    // unavailable in real-life.

    // Unless we're dealing with HTTP/0.9, check that
    // the minimum amount of data has been provided.
    if (tx->is_protocol_0_9 != 0) {
        if ((tx->response_protocol == NULL) || (tx->response_status_number == -1) || (tx->response_message == NULL)) {
            return HTP_ERROR;
        }
    }
    #endif

    // Is the response line valid?
    if ((tx->response_protocol_number == HTP_PROTOCOL_INVALID)
            || (tx->response_status_number == HTP_STATUS_INVALID)
            || (tx->response_status_number < HTP_VALID_STATUS_MIN)
            || (tx->response_status_number > HTP_VALID_STATUS_MAX)) {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Invalid response line.");
        tx->flags |= HTP_STATUS_LINE_INVALID;
    }

    // Run hook HTP_RESPONSE_LINE
    int rc = htp_hook_run_all(tx->connp->cfg->hook_response_line, tx->connp);
    if (rc != HTP_OK) return rc;

    return HTP_OK;
}

htp_status_t htp_tx_res_set_header(htp_tx_t *tx, const char *name, size_t name_len,
        const char *value, size_t value_len, enum htp_alloc_strategy_t alloc) {
    if ((name == NULL) || (value == NULL)) return HTP_ERROR;


    htp_header_t *h = calloc(1, sizeof (htp_header_t));
    if (h == NULL) return HTP_ERROR;

    h->name = copy_or_wrap_mem(name, name_len, alloc);
    if (h->name == NULL) {
        free(h);
        return HTP_ERROR;
    }

    h->value = copy_or_wrap_mem(value, value_len, alloc);
    if (h->value == NULL) {
        bstr_free(h->name);
        free(h);
        return HTP_ERROR;
    }

    if (htp_table_add(tx->response_headers, h->name, h) != HTP_OK) {
        bstr_free(h->name);
        bstr_free(h->value);
        free(h);
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_res_set_headers_clear(htp_tx_t *tx) {
    if (tx->response_headers == NULL) return HTP_ERROR;

    htp_header_t *h = NULL;
    for (int i = 0, n = htp_table_size(tx->response_headers); i < n; i++) {
        h = htp_table_get_index(tx->response_headers, i, NULL);
        bstr_free(h->name);
        bstr_free(h->value);
        free(h);
    }

    htp_table_destroy(tx->response_headers);

    tx->response_headers = htp_table_create(32);
    if (tx->response_headers == NULL) return HTP_ERROR;

    return HTP_OK;
}

static htp_status_t htp_tx_res_process_body_data_decompressor_callback(htp_tx_data_t *d) {
    #if HTP_DEBUG
    fprint_raw_data(stderr, __FUNCTION__, d->data, d->len);
    #endif

    // Keep track of actual response body length.
    d->tx->response_entity_len += d->len;

    // Invoke all callbacks.
    int rc = htp_res_run_hook_body_data(d->tx->connp, d);
    if (rc != HTP_OK) return HTP_ERROR;

    return HTP_OK;
}

htp_status_t htp_tx_res_process_body_data(htp_tx_t *tx, const void *data, size_t len) {
    #ifdef HTP_DEBUG
    fprint_raw_data(stderr, __FUNCTION__, data, len);
    #endif

    htp_tx_data_t d;

    d.tx = tx;
    d.data = (unsigned char *) data;
    d.len = len;

    // Keep track of body size before decompression.
    tx->response_message_len += d.len;

    switch (tx->response_content_encoding_processing) {
        case HTP_COMPRESSION_GZIP:
        case HTP_COMPRESSION_DEFLATE:
            // Send data buffer to the decompressor.
            tx->connp->out_decompressor->decompress(tx->connp->out_decompressor, &d);

            if (data == NULL) {
                // Shut down the decompressor, if we used one.
                tx->connp->out_decompressor->destroy(tx->connp->out_decompressor);
                tx->connp->out_decompressor = NULL;
            }
            break;

        case HTP_COMPRESSION_NONE:
            // When there's no decompression, response_entity_len.
            // is identical to response_message_len.
            tx->response_entity_len += d.len;

            int rc = htp_res_run_hook_body_data(tx->connp, &d);
            if (rc != HTP_OK) return HTP_ERROR;
            break;

        default:
            // Internal error.
            htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                    "[Internal Error] Invalid tx->response_content_encoding_processing value: %d",
                    tx->response_content_encoding_processing);
            return HTP_ERROR;
            break;
    }

    return HTP_OK;
}

htp_status_t htp_tx_state_request_complete(htp_tx_t *tx) {
    // Finalize request body.
    if (htp_tx_req_has_body(tx)) {
        htp_status_t rc = htp_tx_req_process_body_data(tx, NULL, 0);
        if (rc != HTP_OK) return rc;
    }

    // Run hook REQUEST_COMPLETE.
    htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_request_complete, tx->connp);
    if (rc != HTP_OK) return rc;

    // Clean-up.
    if (tx->connp->put_file != NULL) {
        bstr_free(tx->connp->put_file->filename);
        free(tx->connp->put_file);
        tx->connp->put_file = NULL;
    }

    // Update the transaction status, but only if it not move
    // on already. This may happen when we're processing a CONNECT
    // request and need to wait for the response to determine how
    // to continue to treat the rest of the TCP stream.
    if (tx->progress < HTP_REQUEST_COMPLETE) {
        tx->progress = HTP_REQUEST_COMPLETE;
    }

    if (tx->is_protocol_0_9) {
        tx->connp->in_state = htp_connp_REQ_IGNORE_DATA_AFTER_HTTP_0_9;
    } else {
        tx->connp->in_state = htp_connp_REQ_IDLE;
    }

    tx->connp->in_tx = NULL;

    return HTP_OK;
}

htp_status_t htp_tx_state_request_start(htp_tx_t *tx) {
    // Run hook REQUEST_START.
    int rc = htp_hook_run_all(tx->connp->cfg->hook_request_start, tx->connp);
    if (rc != HTP_OK) return rc;

    // Change state into request line parsing.
    tx->connp->in_state = htp_connp_REQ_LINE;
    tx->connp->in_tx->progress = HTP_REQUEST_LINE;

    return HTP_OK;
}

htp_status_t htp_tx_state_request_headers(htp_tx_t *tx) {
    // Did this request arrive in multiple chunks?
    // XXX Will the below be correct on a request that has trailers?
    if (tx->connp->in_chunk_count != tx->connp->in_chunk_request_index) {
        tx->flags |= HTP_MULTI_PACKET_HEAD;
    }

    // If we're in TX_PROGRESS_REQ_HEADERS that means that this is the
    // first time we're processing headers in a request. Otherwise,
    // we're dealing with trailing headers.
    if (tx->progress > HTP_REQUEST_HEADERS) {
        // Request trailers.

        // Run hook HTP_REQUEST_TRAILER.
        htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_request_trailer, tx->connp);
        if (rc != HTP_OK) return rc;

        // Finalize sending raw header data.
        rc = htp_connp_req_receiver_finalize_clear(tx->connp);
        if (rc != HTP_OK) return rc;

        // Completed parsing this request; finalize it now.
        tx->connp->in_state = htp_connp_REQ_FINALIZE;
    } else if (tx->progress >= HTP_REQUEST_LINE) {
        // Request headers.

        htp_status_t rc = htp_tx_process_request_headers(tx);
        if (rc != HTP_OK) return rc;

        tx->connp->in_state = htp_connp_REQ_CONNECT_CHECK;
    } else {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "[Internal Error] Invalid tx progress: %d", tx->progress);

        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_state_request_line(htp_tx_t *tx) {
    // Determine how to process the request URI.

    if (tx->request_method_number == HTP_M_CONNECT) {
        // When CONNECT is used, the request URI contains an authority string.
        if (htp_parse_uri_hostport(tx->connp, tx->request_uri, tx->parsed_uri_raw) != HTP_OK) {
            return HTP_ERROR;
        }
    } else {
        // Parse the request URI into htp_tx_t::parsed_uri_raw.
        if (htp_parse_uri(tx->request_uri, &(tx->parsed_uri_raw)) != HTP_OK) {
            return HTP_ERROR;
        }
    }

    // Build htp_tx_t::parsed_uri, but only if it was not explicitly set already.
    if (tx->parsed_uri == NULL) {
        tx->parsed_uri = htp_uri_alloc();
        if (tx->parsed_uri == NULL) return HTP_ERROR;

        // Keep the original URI components, but create a copy which we can normalize and use internally.
        if (htp_normalize_parsed_uri(tx->connp, tx->parsed_uri_raw, tx->parsed_uri) != HTP_OK) {
            return HTP_ERROR;
        }
    }

    // Check parsed_uri hostname.
    if (tx->parsed_uri->hostname != NULL) {
        if (htp_validate_hostname(tx->parsed_uri->hostname) == 0) {
            tx->flags |= HTP_HOSTU_INVALID;
        }
    }

    // Run hook REQUEST_URI_NORMALIZE.
    htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_request_uri_normalize, tx->connp);
    if (rc != HTP_OK) return rc;


    // Run hook REQUEST_LINE.
    rc = htp_hook_run_all(tx->connp->cfg->hook_request_line, tx->connp);
    if (rc != HTP_OK) return rc;

    // Move on to the next phase.
    tx->connp->in_state = htp_connp_REQ_PROTOCOL;

    return HTP_OK;
}

htp_status_t htp_tx_state_response_complete(htp_tx_t *tx) {
    return htp_tx_state_response_complete_ex(tx, 1 /* hybrid mode */);
}

htp_status_t htp_tx_state_response_complete_ex(htp_tx_t *tx, int hybrid_mode) {
    if (tx->progress != HTP_RESPONSE_COMPLETE) {
        tx->progress = HTP_RESPONSE_COMPLETE;

        // Run the last RESPONSE_BODY_DATA HOOK, but only if there was a response body present.
        if (tx->response_transfer_coding != HTP_CODING_NO_BODY) {
            htp_tx_res_process_body_data(tx, NULL, 0);
        }

        // Run hook RESPONSE_COMPLETE.
        htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_response_complete, tx->connp);
        if (rc != HTP_OK) return rc;
    }

    if (!hybrid_mode) {
        // Check if the inbound parser is waiting on us. If it is, that means that
        // there might be request data that the inbound parser hasn't consumed yet.
        // If we don't stop parsing we might encounter a response without a request,
        // which is why we want to return straight away before processing any data.
        //
        // This situation will occur any time the parser needs to see the server
        // respond to a particular situation before it can decide how to proceed. For
        // example, when a CONNECT is sent, different paths are used when it is accepted
        // and when it is not accepted.
        //
        // It is not enough to check only in_status here. Because of pipelining, it's possible
        // that many inbound transactions have been processed, and that the parser is
        // waiting on a response that we have not seen yet.
        if ((tx->connp->in_status == HTP_STREAM_DATA_OTHER) && (tx->connp->in_tx == tx->connp->out_tx)) {
            return HTP_DATA_OTHER;
        }

        // Do we have a signal to yield to inbound processing at
        // the end of the next transaction?
        if (tx->connp->out_data_other_at_tx_end) {
            // We do. Let's yield then.
            tx->connp->out_data_other_at_tx_end = 0;
            return HTP_DATA_OTHER;
        }

        // In streaming processing, we destroy the transaction
        // because it will not be needed any more.
        if (tx->connp->cfg->tx_auto_destroy) {
            htp_tx_destroy(tx->connp->out_tx);
        }
    }

    // Disconnect from the transaction
    tx->connp->out_tx = NULL;

    tx->connp->out_state = htp_connp_RES_IDLE;

    return HTP_OK;
}

htp_status_t htp_tx_state_response_headers(htp_tx_t *tx) {
    // Check for compression.

    // Determine content encoding.
    tx->response_content_encoding = HTP_COMPRESSION_NONE;
    htp_header_t *ce = htp_table_get_c(tx->response_headers, "content-encoding");
    if (ce != NULL) {
        if ((bstr_cmp_c(ce->value, "gzip") == 0) || (bstr_cmp_c(ce->value, "x-gzip") == 0)) {
            tx->response_content_encoding = HTP_COMPRESSION_GZIP;
        } else if ((bstr_cmp_c(ce->value, "deflate") == 0) || (bstr_cmp_c(ce->value, "x-deflate") == 0)) {
            tx->response_content_encoding = HTP_COMPRESSION_DEFLATE;
        }
    }

    // Configure decompression, if enabled in the configuration.
    if (tx->connp->cfg->response_decompression_enabled) {
        tx->response_content_encoding_processing = tx->response_content_encoding;
    } else {
        tx->response_content_encoding_processing = HTP_COMPRESSION_NONE;
    }

    // Finalize sending raw header data.
    htp_status_t rc = htp_connp_res_receiver_finalize_clear(tx->connp);
    if (rc != HTP_OK) return rc;

    // Run hook RESPONSE_HEADERS.
    rc = htp_hook_run_all(tx->connp->cfg->hook_response_headers, tx->connp);
    if (rc != HTP_OK) return rc;

    // Initialize the decompression engine as necessary. We can deal with three
    // scenarios:
    //
    // 1. Decompression is enabled, compression indicated in headers, and we decompress.
    //
    // 2. As above, but the user disables decompression by setting response_content_encoding
    //    to COMPRESSION_NONE.
    //
    // 3. Decompression is disabled and we do not attempt to enable it, but the user
    //    forces decompression by setting response_content_encoding to one of the
    //    supported algorithms.
    if ((tx->response_content_encoding_processing == HTP_COMPRESSION_GZIP) || (tx->response_content_encoding_processing == HTP_COMPRESSION_DEFLATE)) {
        if (tx->connp->out_decompressor != NULL) {
            tx->connp->out_decompressor->destroy(tx->connp->out_decompressor);
            tx->connp->out_decompressor = NULL;
        }

        tx->connp->out_decompressor = (htp_decompressor_t *) htp_gzip_decompressor_create(tx->connp,
                tx->response_content_encoding_processing);
        if (tx->connp->out_decompressor == NULL) return HTP_ERROR;
        tx->connp->out_decompressor->callback = htp_tx_res_process_body_data_decompressor_callback;
    } else if (tx->response_content_encoding_processing != HTP_COMPRESSION_NONE) {
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_state_response_start(htp_tx_t *tx) {
    tx->connp->out_tx = tx;

    // Run hook RESPONSE_START.
    int rc = htp_hook_run_all(tx->connp->cfg->hook_response_start, tx->connp);
    if (rc != HTP_OK) return rc;

    // Change state into response line parsing, except if we're following
    // a HTTP/0.9 request (no status line or response headers).
    if (tx->is_protocol_0_9) {
        tx->response_transfer_coding = HTP_CODING_IDENTITY;
        tx->response_content_encoding_processing = HTP_COMPRESSION_NONE;
        tx->progress = HTP_RESPONSE_BODY;
        tx->connp->out_state = htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE;
        tx->connp->out_body_data_left = -1;
    } else {
        tx->connp->out_state = htp_connp_RES_LINE;
        tx->progress = HTP_RESPONSE_LINE;
    }

    return HTP_OK;
}

/**
 * Register callback for the transaction-specific REQUEST_BODY_DATA hook.
 *
 * @param[in] tx
 * @param[in] callback_fn
 */
void htp_tx_register_request_body_data(htp_tx_t *tx, int (*callback_fn)(htp_tx_data_t *)) {
    htp_hook_register(&tx->hook_request_body_data, (htp_callback_fn_t) callback_fn);
}

/**
 * Register callback for the transaction-specific RESPONSE_BODY_DATA hook.
 *
 * @param[in] tx
 * @param[in] callback_fn
 */
void htp_tx_register_response_body_data(htp_tx_t *tx, int (*callback_fn)(htp_tx_data_t *)) {
    htp_hook_register(&tx->hook_response_body_data, (htp_callback_fn_t) callback_fn);
}
