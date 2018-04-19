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

#include "htp_config_auto.h"

#include "htp_private.h"

static bstr *copy_or_wrap_mem(const void *data, size_t len, enum htp_alloc_strategy_t alloc) {
    if (data == NULL) return NULL;

    if (alloc == HTP_ALLOC_REUSE) {
        return bstr_wrap_mem(data, len);
    } else {
        return bstr_dup_mem(data, len);
    }
}

htp_tx_t *htp_tx_create(htp_connp_t *connp) {
    if (connp == NULL) return NULL;

    htp_tx_t *tx = calloc(1, sizeof (htp_tx_t));
    if (tx == NULL) return NULL;

    tx->connp = connp;
    tx->conn = connp->conn;
    tx->index = htp_list_size(tx->conn->transactions);
    tx->cfg = connp->cfg;
    tx->is_config_shared = HTP_CONFIG_SHARED;

    // Request fields.

    tx->request_progress = HTP_REQUEST_NOT_STARTED;
    tx->request_protocol_number = HTP_PROTOCOL_UNKNOWN;
    tx->request_content_length = -1;

    tx->parsed_uri_raw = htp_uri_alloc();
    if (tx->parsed_uri_raw == NULL) {
        htp_tx_destroy_incomplete(tx);
        return NULL;
    }

    tx->request_headers = htp_table_create(32);
    if (tx->request_headers == NULL) {
        htp_tx_destroy_incomplete(tx);
        return NULL;
    }

    tx->request_params = htp_table_create(32);
    if (tx->request_params == NULL) {
        htp_tx_destroy_incomplete(tx);
        return NULL;
    }

    // Response fields.

    tx->response_progress = HTP_RESPONSE_NOT_STARTED;
    tx->response_status = NULL;
    tx->response_status_number = HTP_STATUS_UNKNOWN;
    tx->response_protocol_number = HTP_PROTOCOL_UNKNOWN;
    tx->response_content_length = -1;

    tx->response_headers = htp_table_create(32);
    if (tx->response_headers == NULL) {
        htp_tx_destroy_incomplete(tx);
        return NULL;
    }

    htp_list_add(tx->conn->transactions, tx);

    return tx;
}

htp_status_t htp_tx_destroy(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    if (!htp_tx_is_complete(tx)) return HTP_ERROR;

    htp_tx_destroy_incomplete(tx);

    return HTP_OK;
}

void htp_tx_destroy_incomplete(htp_tx_t *tx) {
    if (tx == NULL) return;

    // Disconnect transaction from other structures.
    htp_conn_remove_tx(tx->conn, tx);
    htp_connp_tx_remove(tx->connp, tx);

    // Request fields.

    bstr_free(tx->request_line);
    bstr_free(tx->request_method);
    bstr_free(tx->request_uri);
    bstr_free(tx->request_protocol);
    bstr_free(tx->request_content_type);
    bstr_free(tx->request_hostname);
    htp_uri_free(tx->parsed_uri_raw);
    htp_uri_free(tx->parsed_uri);
    bstr_free(tx->request_auth_username);
    bstr_free(tx->request_auth_password);

    // Request_headers.
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

    // Request parsers.

    htp_urlenp_destroy(tx->request_urlenp_query);
    htp_urlenp_destroy(tx->request_urlenp_body);
    htp_mpartp_destroy(tx->request_mpartp);

    // Request parameters.

    htp_param_t *param = NULL;
    for (size_t i = 0, n = htp_table_size(tx->request_params); i < n; i++) {
        param = htp_table_get_index(tx->request_params, i, NULL);
        bstr_free(param->name);
        bstr_free(param->value);
        free(param);
    }

    htp_table_destroy(tx->request_params);

    // Request cookies.

    if (tx->request_cookies != NULL) {
        bstr *b = NULL;
        for (size_t i = 0, n = htp_table_size(tx->request_cookies); i < n; i++) {
            b = htp_table_get_index(tx->request_cookies, i, NULL);
            bstr_free(b);
        }

        htp_table_destroy(tx->request_cookies);
    }

    htp_hook_destroy(tx->hook_request_body_data);

    // Response fields.

    bstr_free(tx->response_line);
    bstr_free(tx->response_protocol);
    bstr_free(tx->response_status);
    bstr_free(tx->response_message);
    bstr_free(tx->response_content_type);

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

    // If we're using a private configuration structure, destroy it.
    if (tx->is_config_shared == HTP_CONFIG_PRIVATE) {
        htp_config_destroy(tx->cfg);
    }

    free(tx);
}

int htp_tx_get_is_config_shared(const htp_tx_t *tx) {
    if (tx == NULL) return -1;
    return tx->is_config_shared;
}

void *htp_tx_get_user_data(const htp_tx_t *tx) {
    if (tx == NULL) return NULL;
    return tx->user_data;
}

void htp_tx_set_config(htp_tx_t *tx, htp_cfg_t *cfg, int is_cfg_shared) {
    if ((tx == NULL) || (cfg == NULL)) return;

    if ((is_cfg_shared != HTP_CONFIG_PRIVATE) && (is_cfg_shared != HTP_CONFIG_SHARED)) return;

    // If we're using a private configuration, destroy it.
    if (tx->is_config_shared == HTP_CONFIG_PRIVATE) {
        htp_config_destroy(tx->cfg);
    }

    tx->cfg = cfg;
    tx->is_config_shared = is_cfg_shared;
}

void htp_tx_set_user_data(htp_tx_t *tx, void *user_data) {
    if (tx == NULL) return;
    tx->user_data = user_data;
}

htp_status_t htp_tx_req_add_param(htp_tx_t *tx, htp_param_t *param) {
    if ((tx == NULL) || (param == NULL)) return HTP_ERROR;

    if (tx->cfg->parameter_processor != NULL) {
        if (tx->cfg->parameter_processor(param) != HTP_OK) return HTP_ERROR;
    }

    return htp_table_addk(tx->request_params, param->name, param);
}

htp_param_t *htp_tx_req_get_param(htp_tx_t *tx, const char *name, size_t name_len) {
    if ((tx == NULL) || (name == NULL)) return NULL;
    return htp_table_get_mem(tx->request_params, name, name_len);
}

htp_param_t *htp_tx_req_get_param_ex(htp_tx_t *tx, enum htp_data_source_t source, const char *name, size_t name_len) {
    if ((tx == NULL) || (name == NULL)) return NULL;

    htp_param_t *p = NULL;

    for (size_t i = 0, n = htp_table_size(tx->request_params); i < n; i++) {
        p = htp_table_get_index(tx->request_params, i, NULL);
        if (p->source != source) continue;

        if (bstr_cmp_mem_nocase(p->name, name, name_len) == 0) return p;
    }

    return NULL;
}

int htp_tx_req_has_body(const htp_tx_t *tx) {
    if (tx == NULL) return -1;

    if ((tx->request_transfer_coding == HTP_CODING_IDENTITY) || (tx->request_transfer_coding == HTP_CODING_CHUNKED)) {
        return 1;
    }

    return 0;
}

htp_status_t htp_tx_req_set_header(htp_tx_t *tx, const char *name, size_t name_len,
        const char *value, size_t value_len, enum htp_alloc_strategy_t alloc) {
    if ((tx == NULL) || (name == NULL) || (value == NULL)) return HTP_ERROR;

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
    if ((tx == NULL) || (method == NULL)) return HTP_ERROR;

    tx->request_method = copy_or_wrap_mem(method, method_len, alloc);
    if (tx->request_method == NULL) return HTP_ERROR;

    return HTP_OK;
}

void htp_tx_req_set_method_number(htp_tx_t *tx, enum htp_method_t method_number) {
    if (tx == NULL) return;
    tx->request_method_number = method_number;
}

htp_status_t htp_tx_req_set_uri(htp_tx_t *tx, const char *uri, size_t uri_len, enum htp_alloc_strategy_t alloc) {
    if ((tx == NULL) || (uri == NULL)) return HTP_ERROR;

    tx->request_uri = copy_or_wrap_mem(uri, uri_len, alloc);
    if (tx->request_uri == NULL) return HTP_ERROR;

    return HTP_OK;
}

htp_status_t htp_tx_req_set_protocol(htp_tx_t *tx, const char *protocol, size_t protocol_len, enum htp_alloc_strategy_t alloc) {
    if ((tx == NULL) || (protocol == NULL)) return HTP_ERROR;

    tx->request_protocol = copy_or_wrap_mem(protocol, protocol_len, alloc);
    if (tx->request_protocol == NULL) return HTP_ERROR;

    return HTP_OK;
}

void htp_tx_req_set_protocol_number(htp_tx_t *tx, int protocol_number) {
    if (tx == NULL) return;
    tx->request_protocol_number = protocol_number;
}

void htp_tx_req_set_protocol_0_9(htp_tx_t *tx, int is_protocol_0_9) {
    if (tx == NULL) return;

    if (is_protocol_0_9) {
        tx->is_protocol_0_9 = 1;
    } else {
        tx->is_protocol_0_9 = 0;
    }
}

static htp_status_t htp_tx_process_request_headers(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    // Determine if we have a request body, and how it is packaged.

    htp_status_t rc = HTP_OK;

    htp_header_t *cl = htp_table_get_c(tx->request_headers, "content-length");
    htp_header_t *te = htp_table_get_c(tx->request_headers, "transfer-encoding");

    // Check for the Transfer-Encoding header, which would indicate a chunked request body.
    if (te != NULL) {
        // Make sure it contains "chunked" only.
        // TODO The HTTP/1.1 RFC also allows the T-E header to contain "identity", which
        //      presumably should have the same effect as T-E header absence. However, Apache
        //      (2.2.22 on Ubuntu 12.04 LTS) instead errors out with "Unknown Transfer-Encoding: identity".
        //      And it behaves strangely, too, sending a 501 and proceeding to process the request
        //      (e.g., PHP is run), but without the body. It then closes the connection.
        if (bstr_cmp_c_nocase(te->value, "chunked") != 0) {
            // Invalid T-E header value.
            tx->request_transfer_coding = HTP_CODING_INVALID;
            tx->flags |= HTP_REQUEST_INVALID_T_E;
            tx->flags |= HTP_REQUEST_INVALID;
        } else {
            // Chunked encoding is a HTTP/1.1 feature, so check that an earlier protocol
            // version is not used. The flag will also be set if the protocol could not be parsed.
            //
            // TODO IIS 7.0, for example, would ignore the T-E header when it
            //      it is used with a protocol below HTTP 1.1. This should be a
            //      personality trait.
            if (tx->request_protocol_number < HTP_PROTOCOL_1_1) {
                tx->flags |= HTP_REQUEST_INVALID_T_E;
                tx->flags |= HTP_REQUEST_SMUGGLING;
            }

            // If the T-E header is present we are going to use it.
            tx->request_transfer_coding = HTP_CODING_CHUNKED;

            // We are still going to check for the presence of C-L.
            if (cl != NULL) {
                // According to the HTTP/1.1 RFC (section 4.4):
                //
                // "The Content-Length header field MUST NOT be sent
                //  if these two lengths are different (i.e., if a Transfer-Encoding
                //  header field is present). If a message is received with both a
                //  Transfer-Encoding header field and a Content-Length header field,
                //  the latter MUST be ignored."
                //
                tx->flags |= HTP_REQUEST_SMUGGLING;
            }
        }
    } else if (cl != NULL) {
        // Check for a folded C-L header.
        if (cl->flags & HTP_FIELD_FOLDED) {
            tx->flags |= HTP_REQUEST_SMUGGLING;
        }

        // Check for multiple C-L headers.
        if (cl->flags & HTP_FIELD_REPEATED) {
            tx->flags |= HTP_REQUEST_SMUGGLING;
            // TODO Personality trait to determine which C-L header to parse.
            //      At the moment we're parsing the combination of all instances,
            //      which is bound to fail (because it will contain commas).
        }

        // Get the body length.
        tx->request_content_length = htp_parse_content_length(cl->value);
        if (tx->request_content_length < 0) {
            tx->request_transfer_coding = HTP_CODING_INVALID;
            tx->flags |= HTP_REQUEST_INVALID_C_L;
            tx->flags |= HTP_REQUEST_INVALID;
        } else {
            // We have a request body of known length.
            tx->request_transfer_coding = HTP_CODING_IDENTITY;
        }
    } else {
        // No body.
        tx->request_transfer_coding = HTP_CODING_NO_BODY;
    }

    // If we could not determine the correct body handling,
    // consider the request invalid.
    if (tx->request_transfer_coding == HTP_CODING_UNKNOWN) {
        tx->request_transfer_coding = HTP_CODING_INVALID;
        tx->flags |= HTP_REQUEST_INVALID;
    }

    // Check for PUT requests, which we need to treat as file uploads.
    if (tx->request_method_number == HTP_M_PUT) {
        if (htp_tx_req_has_body(tx)) {
            // Prepare to treat PUT request body as a file.
            
            tx->connp->put_file = calloc(1, sizeof (htp_file_t));
            if (tx->connp->put_file == NULL) return HTP_ERROR;

            tx->connp->put_file->fd = -1;
            tx->connp->put_file->source = HTP_FILE_PUT;
        } else {
            // TODO Warn about PUT request without a body.
        }
    }

    // Determine hostname.

    // Use the hostname from the URI, when available.   
    if (tx->parsed_uri->hostname != NULL) {
        tx->request_hostname = bstr_dup(tx->parsed_uri->hostname);
        if (tx->request_hostname == NULL) return HTP_ERROR;
    }

    tx->request_port_number = tx->parsed_uri->port_number;

    // Examine the Host header.

    htp_header_t *h = htp_table_get_c(tx->request_headers, "host");
    if (h == NULL) {
        // No host information in the headers.

        // HTTP/1.1 requires host information in the headers.
        if (tx->request_protocol_number >= HTP_PROTOCOL_1_1) {
            tx->flags |= HTP_HOST_MISSING;
        }
    } else {
        // Host information available in the headers.

        bstr *hostname;
        int port;

        rc = htp_parse_header_hostport(h->value, &hostname, NULL, &port, &(tx->flags));
        if (rc != HTP_OK) return rc;

        if (hostname != NULL) {
            // The host information in the headers is valid.

            // Is there host information in the URI?
            if (tx->request_hostname == NULL) {
                // There is no host information in the URI. Place the
                // hostname from the headers into the parsed_uri structure.
                tx->request_hostname = hostname;
                tx->request_port_number = port;
            } else {
                // The host information appears in the URI and in the headers. The
                // HTTP RFC states that we should ignore the header copy.
                
                // Check for different hostnames.
                if (bstr_cmp_nocase(hostname, tx->request_hostname) != 0) {                    
                    tx->flags |= HTP_HOST_AMBIGUOUS;
                }

                // Check for different ports.
                if (((tx->request_port_number != -1)&&(port != -1))&&(tx->request_port_number != port)) {
                    tx->flags |= HTP_HOST_AMBIGUOUS;
                }

                bstr_free(hostname);
            }
        } else {
            // Invalid host information in the headers.

            if (tx->request_hostname != NULL) {
                // Raise the flag, even though the host information in the headers is invalid.
                tx->flags |= HTP_HOST_AMBIGUOUS;
            }
        }
    }

    // Determine Content-Type.
    htp_header_t *ct = htp_table_get_c(tx->request_headers, "content-type");
    if (ct != NULL) {
        rc = htp_parse_ct_header(ct->value, &tx->request_content_type);
        if (rc != HTP_OK) return rc;
    }

    // Parse cookies.
    if (tx->connp->cfg->parse_request_cookies) {
        rc = htp_parse_cookies_v0(tx->connp);
        if (rc != HTP_OK) return rc;
    }

    // Parse authentication information.
    if (tx->connp->cfg->parse_request_auth) {
        rc = htp_parse_authorization(tx->connp);
        if (rc == HTP_DECLINED) {
            // Don't fail the stream if an authorization header is invalid, just set a flag.
            tx->flags |= HTP_AUTH_INVALID;
        } else {
            if (rc != HTP_OK) return rc;
        }
    }

    // Finalize sending raw header data.
    rc = htp_connp_req_receiver_finalize_clear(tx->connp);
    if (rc != HTP_OK) return rc;

    // Run hook REQUEST_HEADERS.
    rc = htp_hook_run_all(tx->connp->cfg->hook_request_headers, tx);
    if (rc != HTP_OK) return rc;

    // We cannot proceed if the request is invalid.
    if (tx->flags & HTP_REQUEST_INVALID) {
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_req_process_body_data(htp_tx_t *tx, const void *data, size_t len) {
    if ((tx == NULL) || (data == NULL)) return HTP_ERROR;
    if (len == 0) return HTP_OK;

    return htp_tx_req_process_body_data_ex(tx, data, len);
}

htp_status_t htp_tx_req_process_body_data_ex(htp_tx_t *tx, const void *data, size_t len) {
    if (tx == NULL) return HTP_ERROR;

    // NULL data is allowed in this private function; it's
    // used to indicate the end of request body.

    // Keep track of the body length.
    tx->request_entity_len += len;

    // Send data to the callbacks.

    htp_tx_data_t d;
    d.tx = tx;
    d.data = (unsigned char *) data;
    d.len = len;

    htp_status_t rc = htp_req_run_hook_body_data(tx->connp, &d);
    if (rc != HTP_OK) {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Request body data callback returned error (%d)", rc);
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_req_set_headers_clear(htp_tx_t *tx) {
    if ((tx == NULL) || (tx->request_headers == NULL)) return HTP_ERROR;

    htp_header_t *h = NULL;
    for (size_t i = 0, n = htp_table_size(tx->request_headers); i < n; i++) {
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
    if ((tx == NULL) || (line == NULL) || (line_len == 0)) return HTP_ERROR;

    tx->request_line = copy_or_wrap_mem(line, line_len, alloc);
    if (tx->request_line == NULL) return HTP_ERROR;

    if (tx->connp->cfg->parse_request_line(tx->connp) != HTP_OK) return HTP_ERROR;

    return HTP_OK;
}

void htp_tx_req_set_parsed_uri(htp_tx_t *tx, htp_uri_t *parsed_uri) {
    if ((tx == NULL) || (parsed_uri == NULL)) return;

    if (tx->parsed_uri != NULL) {
        htp_uri_free(tx->parsed_uri);
    }

    tx->parsed_uri = parsed_uri;
}

htp_status_t htp_tx_res_set_status_line(htp_tx_t *tx, const char *line, size_t line_len, enum htp_alloc_strategy_t alloc) {
    if ((tx == NULL) || (line == NULL) || (line_len == 0)) return HTP_ERROR;

    tx->response_line = copy_or_wrap_mem(line, line_len, alloc);
    if (tx->response_line == NULL) return HTP_ERROR;

    if (tx->connp->cfg->parse_response_line(tx->connp) != HTP_OK) return HTP_ERROR;

    return HTP_OK;
}

void htp_tx_res_set_protocol_number(htp_tx_t *tx, int protocol_number) {
    if (tx == NULL) return;
    tx->response_protocol_number = protocol_number;
}

void htp_tx_res_set_status_code(htp_tx_t *tx, int status_code) {
    if (tx == NULL) return;
    tx->response_status_number = status_code;
}

htp_status_t htp_tx_res_set_status_message(htp_tx_t *tx, const char *msg, size_t msg_len, enum htp_alloc_strategy_t alloc) {
    if ((tx == NULL) || (msg == NULL)) return HTP_ERROR;

    if (tx->response_message != NULL) {
        bstr_free(tx->response_message);
    }

    tx->response_message = copy_or_wrap_mem(msg, msg_len, alloc);
    if (tx->response_message == NULL) return HTP_ERROR;

    return HTP_OK;
}

htp_status_t htp_tx_state_response_line(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

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
    if (tx->response_protocol_number == HTP_PROTOCOL_INVALID) {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                "Invalid response line: invalid protocol");
        tx->flags |= HTP_STATUS_LINE_INVALID;
    }
    if ((tx->response_status_number == HTP_STATUS_INVALID)
            || (tx->response_status_number < HTP_VALID_STATUS_MIN)
            || (tx->response_status_number > HTP_VALID_STATUS_MAX)) {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                "Invalid response line: invalid response status %d.",
                tx->response_status_number);
        tx->response_status_number = HTP_STATUS_INVALID;
        tx->flags |= HTP_STATUS_LINE_INVALID;
    }

    // Run hook HTP_RESPONSE_LINE
    htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_response_line, tx);
    if (rc != HTP_OK) return rc;

    return HTP_OK;
}

htp_status_t htp_tx_res_set_header(htp_tx_t *tx, const char *name, size_t name_len,
        const char *value, size_t value_len, enum htp_alloc_strategy_t alloc) {
    if ((tx == NULL) || (name == NULL) || (value == NULL)) return HTP_ERROR;


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
    if ((tx == NULL) || (tx->response_headers == NULL)) return HTP_ERROR;

    htp_header_t *h = NULL;
    for (size_t i = 0, n = htp_table_size(tx->response_headers); i < n; i++) {
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

void htp_connp_destroy_decompressors(htp_connp_t *connp) {
    htp_decompressor_t *comp = connp->out_decompressor;
    while (comp) {
        htp_decompressor_t *next = comp->next;
        comp->destroy(comp);
        comp = next;
    }
    connp->out_decompressor = NULL;
}

/** \internal
 *
 * Clean up decompressor(s).
 *
 * @param[in] tx
 */
static void htp_tx_res_destroy_decompressors(htp_tx_t *tx) {
    htp_connp_destroy_decompressors(tx->connp);
}

static htp_status_t htp_tx_res_process_body_data_decompressor_callback(htp_tx_data_t *d) {
    if (d == NULL) return HTP_ERROR;

    #if HTP_DEBUG
    fprint_raw_data(stderr, __func__, d->data, d->len);
    #endif

    // Keep track of actual response body length.
    d->tx->response_entity_len += d->len;

    // Invoke all callbacks.
    htp_status_t rc = htp_res_run_hook_body_data(d->tx->connp, d);
    if (rc != HTP_OK) return HTP_ERROR;

    return HTP_OK;
}

htp_status_t htp_tx_res_process_body_data(htp_tx_t *tx, const void *data, size_t len) {
    if ((tx == NULL) || (data == NULL)) return HTP_ERROR;
    if (len == 0) return HTP_OK;
    return htp_tx_res_process_body_data_ex(tx, data, len);
}

htp_status_t htp_tx_res_process_body_data_ex(htp_tx_t *tx, const void *data, size_t len) {
    if (tx == NULL) return HTP_ERROR;

    // NULL data is allowed in this private function; it's
    // used to indicate the end of response body.

    #ifdef HTP_DEBUG
    fprint_raw_data(stderr, __func__, data, len);
    #endif

    htp_tx_data_t d;

    d.tx = tx;
    d.data = (unsigned char *) data;
    d.len = len;
    d.is_last = 0;

    // Keep track of body size before decompression.
    tx->response_message_len += d.len;

    switch (tx->response_content_encoding_processing) {
        case HTP_COMPRESSION_GZIP:
        case HTP_COMPRESSION_DEFLATE:
            // In severe memory stress these could be NULL
            if (tx->connp->out_decompressor == NULL || tx->connp->out_decompressor->decompress == NULL)
                return HTP_ERROR;

            // Send data buffer to the decompressor.
            tx->connp->out_decompressor->decompress(tx->connp->out_decompressor, &d);

            if (data == NULL) {
                // Shut down the decompressor, if we used one.
                htp_tx_res_destroy_decompressors(tx);
            }
            break;

        case HTP_COMPRESSION_NONE:
            // When there's no decompression, response_entity_len.
            // is identical to response_message_len.
            tx->response_entity_len += d.len;

            htp_status_t rc = htp_res_run_hook_body_data(tx->connp, &d);
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

htp_status_t htp_tx_state_request_complete_partial(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    // Finalize request body.
    if (htp_tx_req_has_body(tx)) {
        htp_status_t rc = htp_tx_req_process_body_data_ex(tx, NULL, 0);
        if (rc != HTP_OK) return rc;
    }

    tx->request_progress = HTP_REQUEST_COMPLETE;

    // Run hook REQUEST_COMPLETE.
    htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_request_complete, tx);
    if (rc != HTP_OK) return rc;

    // Clean-up.
    if (tx->connp->put_file != NULL) {
        bstr_free(tx->connp->put_file->filename);
        free(tx->connp->put_file);
        tx->connp->put_file = NULL;
    }

    return HTP_OK;
}

htp_status_t htp_tx_state_request_complete(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    if (tx->request_progress != HTP_REQUEST_COMPLETE) {
        htp_status_t rc = htp_tx_state_request_complete_partial(tx);
        if (rc != HTP_OK) return rc;
    }

    // Make a copy of the connection parser pointer, so that
    // we don't have to reference it via tx, which may be
    // destroyed later.
    htp_connp_t *connp = tx->connp;

    // Determine what happens next, and remove this transaction from the parser.
    if (tx->is_protocol_0_9) {
        connp->in_state = htp_connp_REQ_IGNORE_DATA_AFTER_HTTP_0_9;
    } else {
        connp->in_state = htp_connp_REQ_IDLE;
    }

    // Check if the entire transaction is complete. This call may
    // destroy the transaction, if auto-destroy is enabled.
    htp_tx_finalize(tx);

    // At this point, tx may no longer be valid.

    connp->in_tx = NULL;

    return HTP_OK;
}

htp_status_t htp_tx_state_request_start(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    // Run hook REQUEST_START.
    htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_request_start, tx);
    if (rc != HTP_OK) return rc;

    // Change state into request line parsing.
    tx->connp->in_state = htp_connp_REQ_LINE;
    tx->connp->in_tx->request_progress = HTP_REQUEST_LINE;

    return HTP_OK;
}

htp_status_t htp_tx_state_request_headers(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    // If we're in HTP_REQ_HEADERS that means that this is the
    // first time we're processing headers in a request. Otherwise,
    // we're dealing with trailing headers.
    if (tx->request_progress > HTP_REQUEST_HEADERS) {
        // Request trailers.

        // Run hook HTP_REQUEST_TRAILER.
        htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_request_trailer, tx);
        if (rc != HTP_OK) return rc;

        // Finalize sending raw header data.
        rc = htp_connp_req_receiver_finalize_clear(tx->connp);
        if (rc != HTP_OK) return rc;

        // Completed parsing this request; finalize it now.
        tx->connp->in_state = htp_connp_REQ_FINALIZE;
    } else if (tx->request_progress >= HTP_REQUEST_LINE) {
        // Request headers.

        // Did this request arrive in multiple data chunks?
        if (tx->connp->in_chunk_count != tx->connp->in_chunk_request_index) {
            tx->flags |= HTP_MULTI_PACKET_HEAD;
        }

        htp_status_t rc = htp_tx_process_request_headers(tx);
        if (rc != HTP_OK) return rc;

        tx->connp->in_state = htp_connp_REQ_CONNECT_CHECK;
    } else {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "[Internal Error] Invalid tx progress: %d", tx->request_progress);

        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_state_request_line(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

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
        if (htp_normalize_parsed_uri(tx, tx->parsed_uri_raw, tx->parsed_uri) != HTP_OK) {
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
    htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_request_uri_normalize, tx);
    if (rc != HTP_OK) return rc;


    // Run hook REQUEST_LINE.
    rc = htp_hook_run_all(tx->connp->cfg->hook_request_line, tx);
    if (rc != HTP_OK) return rc;

    // Move on to the next phase.
    tx->connp->in_state = htp_connp_REQ_PROTOCOL;

    return HTP_OK;
}

htp_status_t htp_tx_state_response_complete(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;
    return htp_tx_state_response_complete_ex(tx, 1 /* hybrid mode */);
}

htp_status_t htp_tx_finalize(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    if (!htp_tx_is_complete(tx)) return HTP_OK;

    // Run hook TRANSACTION_COMPLETE.
    htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_transaction_complete, tx);
    if (rc != HTP_OK) return rc;

    // In streaming processing, we destroy the transaction because it will not be needed any more.
    if (tx->connp->cfg->tx_auto_destroy) {
        htp_tx_destroy(tx);
    }

    return HTP_OK;
}

htp_status_t htp_tx_state_response_complete_ex(htp_tx_t *tx, int hybrid_mode) {
    if (tx == NULL) return HTP_ERROR;

    if (tx->response_progress != HTP_RESPONSE_COMPLETE) {
        tx->response_progress = HTP_RESPONSE_COMPLETE;

        // Run the last RESPONSE_BODY_DATA HOOK, but only if there was a response body present.
        if (tx->response_transfer_coding != HTP_CODING_NO_BODY) {
            htp_tx_res_process_body_data_ex(tx, NULL, 0);
        }

        // Run hook RESPONSE_COMPLETE.
        htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_response_complete, tx);
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
    }

    // Make a copy of the connection parser pointer, so that
    // we don't have to reference it via tx, which may be destroyed later.
    htp_connp_t *connp = tx->connp;

    // Finalize the transaction. This may call may destroy the transaction, if auto-destroy is enabled.
    htp_status_t rc = htp_tx_finalize(tx);
    if (rc != HTP_OK) return rc;

    // Disconnect transaction from the parser.
    connp->out_tx = NULL;

    connp->out_state = htp_connp_RES_IDLE;

    return HTP_OK;
}

/**
 *  @internal
 *  @brief split input into tokens separated by "seps"
 *  @param seps nul-terminated string: each character is a separator
 */
static int get_token(const unsigned char *in, size_t in_len, const char *seps,
    unsigned char **ret_tok_ptr, size_t *ret_tok_len)
{
    #if HTP_DEBUG
    fprintf(stderr, "INPUT %"PRIuMAX, (uintmax_t)in_len);
    fprint_raw_data(stderr, __func__, in, in_len);
    #endif

    size_t i = 0;

    /* skip leading 'separators' */
    while (i < in_len)
    {
        int match = 0;
        for (const char *s = seps; *s != '\0'; s++) {
            if (in[i] == *s) {
                match++;
                break;
            }
        }
        if (!match)
            break;

        i++;
    }
    if (i >= in_len)
        return 0;

    in += i;
    in_len -= i;

    #if HTP_DEBUG
    fprintf(stderr, "INPUT (POST SEP STRIP) %"PRIuMAX, (uintmax_t)in_len);
    fprint_raw_data(stderr, __func__, in, in_len);
    #endif

    for (i = 0; i < in_len; i++)
    {
        for (const char *s = seps; *s != '\0'; s++) {
            if (in[i] == *s) {
                *ret_tok_ptr = (unsigned char *)in;
                *ret_tok_len = i;
                return 1;
            }
        }
    }

    *ret_tok_ptr = (unsigned char *)in;
    *ret_tok_len = in_len;
    return 1;
}

htp_status_t htp_tx_state_response_headers(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    // Check for compression.

    // Determine content encoding.

    int ce_multi_comp = 0;
    tx->response_content_encoding = HTP_COMPRESSION_NONE;
    htp_header_t *ce = htp_table_get_c(tx->response_headers, "content-encoding");
    if (ce != NULL) {
        /* fast paths: regular gzip and friends */
        if ((bstr_cmp_c_nocase(ce->value, "gzip") == 0) || (bstr_cmp_c_nocase(ce->value, "x-gzip") == 0)) {
            tx->response_content_encoding = HTP_COMPRESSION_GZIP;
        } else if ((bstr_cmp_c_nocase(ce->value, "deflate") == 0) || (bstr_cmp_c_nocase(ce->value, "x-deflate") == 0)) {
            tx->response_content_encoding = HTP_COMPRESSION_DEFLATE;
        } else if (bstr_cmp_c_nocase(ce->value, "inflate") == 0) {
            // ignore
        } else {
            /* exceptional cases: enter slow path */
            ce_multi_comp = 1;
        }
    }

    // Configure decompression, if enabled in the configuration.
    if (tx->connp->cfg->response_decompression_enabled) {
        tx->response_content_encoding_processing = tx->response_content_encoding;
    } else {
        tx->response_content_encoding_processing = HTP_COMPRESSION_NONE;
        ce_multi_comp = 0;
    }

    // Finalize sending raw header data.
    htp_status_t rc = htp_connp_res_receiver_finalize_clear(tx->connp);
    if (rc != HTP_OK) return rc;

    // Run hook RESPONSE_HEADERS.
    rc = htp_hook_run_all(tx->connp->cfg->hook_response_headers, tx);
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
    if ((tx->response_content_encoding_processing == HTP_COMPRESSION_GZIP) ||
        (tx->response_content_encoding_processing == HTP_COMPRESSION_DEFLATE) ||
         ce_multi_comp)
    {
        if (tx->connp->out_decompressor != NULL) {
            htp_tx_res_destroy_decompressors(tx);
        }

        /* normal case */
        if (!ce_multi_comp) {
            tx->connp->out_decompressor = htp_gzip_decompressor_create(tx->connp, tx->response_content_encoding_processing);
            if (tx->connp->out_decompressor == NULL) return HTP_ERROR;

            tx->connp->out_decompressor->callback = htp_tx_res_process_body_data_decompressor_callback;

        /* multiple ce value case */
        } else {
            int layers = 0;
            htp_decompressor_t *comp = NULL;

            uint8_t *tok = NULL;
            size_t tok_len = 0;

            uint8_t *input = bstr_ptr(ce->value);
            size_t input_len = bstr_len(ce->value);

            #if HTP_DEBUG
            fprintf(stderr, "INPUT %"PRIuMAX, (uintmax_t)input_len);
            fprint_raw_data(stderr, __func__, input, input_len);
            #endif

            while (input_len > 0 &&
                   get_token(input, input_len, ", ", &tok, &tok_len))
            {
                #if HTP_DEBUG
                fprintf(stderr, "TOKEN %"PRIuMAX, (uintmax_t)tok_len);
                fprint_raw_data(stderr, __func__, tok, tok_len);
                #endif
                enum htp_content_encoding_t cetype = HTP_COMPRESSION_NONE;

                /* check depth limit (0 means no limit) */
                if ((tx->connp->cfg->response_decompression_layer_limit != 0) &&
                    ((++layers) > tx->connp->cfg->response_decompression_layer_limit))
                {
                    htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                            "Too many response content encoding layers");
                    break;
                }

                if (bstr_util_mem_index_of_c_nocase(tok, tok_len, "gzip") != -1) {
                    if (!(bstr_util_cmp_mem(tok, tok_len, "gzip", 4) == 0 ||
                          bstr_util_cmp_mem(tok, tok_len, "x-gzip", 6) == 0)) {
                        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                                "C-E gzip has abnormal value");
                    }
                    cetype = HTP_COMPRESSION_GZIP;
                } else if (bstr_util_mem_index_of_c_nocase(tok, tok_len, "deflate") != -1) {
                    if (!(bstr_util_cmp_mem(tok, tok_len, "deflate", 7) == 0 ||
                          bstr_util_cmp_mem(tok, tok_len, "x-deflate", 9) == 0)) {
                        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                                "C-E deflate has abnormal value");
                    }
                    cetype = HTP_COMPRESSION_DEFLATE;
                } else if (bstr_util_cmp_mem(tok, tok_len, "inflate", 7) == 0) {
                    cetype = HTP_COMPRESSION_NONE;
                } else {
                    // continue
                    htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                            "C-E unknown setting");
                }

                if (cetype != HTP_COMPRESSION_NONE) {
                    if (comp == NULL) {
                        tx->response_content_encoding_processing = cetype;
                        tx->connp->out_decompressor = htp_gzip_decompressor_create(tx->connp, tx->response_content_encoding_processing);
                        if (tx->connp->out_decompressor == NULL) {
                            return HTP_ERROR;
                        }
                        tx->connp->out_decompressor->callback = htp_tx_res_process_body_data_decompressor_callback;
                        comp = tx->connp->out_decompressor;
                    } else {
                        comp->next = htp_gzip_decompressor_create(tx->connp, cetype);
                        if (comp->next == NULL) {
                            return HTP_ERROR;
                        }
                        comp->next->callback = htp_tx_res_process_body_data_decompressor_callback;
                        comp = comp->next;
                    }
                }

                if ((tok_len + 1) >= input_len)
                    break;
                input += (tok_len + 1);
                input_len -= (tok_len + 1);
            }
        }
    } else if (tx->response_content_encoding_processing != HTP_COMPRESSION_NONE) {
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_tx_state_response_start(htp_tx_t *tx) {
    if (tx == NULL) return HTP_ERROR;

    tx->connp->out_tx = tx;

    // Run hook RESPONSE_START.
    htp_status_t rc = htp_hook_run_all(tx->connp->cfg->hook_response_start, tx);
    if (rc != HTP_OK) return rc;

    // Change state into response line parsing, except if we're following
    // a HTTP/0.9 request (no status line or response headers).
    if (tx->is_protocol_0_9) {
        tx->response_transfer_coding = HTP_CODING_IDENTITY;
        tx->response_content_encoding_processing = HTP_COMPRESSION_NONE;
        tx->response_progress = HTP_RESPONSE_BODY;
        tx->connp->out_state = htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE;
        tx->connp->out_body_data_left = -1;
    } else {
        tx->connp->out_state = htp_connp_RES_LINE;
        tx->response_progress = HTP_RESPONSE_LINE;
    }

    /* If at this point we have no method and no uri and our status
     * is still htp_connp_REQ_LINE, we likely have timed out request
     * or a overly long request */
    if (tx->request_method == HTP_M_UNKNOWN && tx->request_uri == NULL && tx->connp->in_state == htp_connp_REQ_LINE) {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Request line incomplete");

        if (htp_connp_REQ_LINE_complete(tx->connp) != HTP_OK) {
            return HTP_ERROR;
        }
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
    if ((tx == NULL) || (callback_fn == NULL)) return;
    htp_hook_register(&tx->hook_request_body_data, (htp_callback_fn_t) callback_fn);
}

/**
 * Register callback for the transaction-specific RESPONSE_BODY_DATA hook.
 *
 * @param[in] tx
 * @param[in] callback_fn
 */
void htp_tx_register_response_body_data(htp_tx_t *tx, int (*callback_fn)(htp_tx_data_t *)) {
    if ((tx == NULL) || (callback_fn == NULL)) return;
    htp_hook_register(&tx->hook_response_body_data, (htp_callback_fn_t) callback_fn);
}

int htp_tx_is_complete(htp_tx_t *tx) {
    if (tx == NULL) return -1;

    // A transaction is considered complete only when both the request and
    // response are complete. (Sometimes a complete response can be seen
    // even while the request is ongoing.)
    if ((tx->request_progress != HTP_REQUEST_COMPLETE) || (tx->response_progress != HTP_RESPONSE_COMPLETE)) {
        return 0;
    } else {
        return 1;
    }
}
