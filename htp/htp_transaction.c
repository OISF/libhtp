/***************************************************************************
 * Copyright (c) 2009-2010, Open Information Security Foundation
 * Copyright (c) 2009-2012, Qualys, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the Qualys, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

#include "htp.h"

/**
 * Creates a new transaction structure.
 *
 * @param cfg
 * @param is_cfg_shared
 * @param conn
 * @return The newly created transaction, or NULL on memory allocation failure.
 */
htp_tx_t *htp_tx_create(htp_cfg_t *cfg, int is_cfg_shared, htp_conn_t *conn) {
    htp_tx_t *tx = calloc(1, sizeof (htp_tx_t));
    if (tx == NULL) return NULL;

    tx->conn = conn;
    tx->cfg = cfg;
    tx->is_cfg_shared = is_cfg_shared;

    tx->conn = conn;

    tx->request_header_lines = cfg->create_list_array(32);
    tx->request_headers = cfg->create_table(32);
    tx->request_line_nul_offset = -1;
    tx->parsed_uri = calloc(1, sizeof (htp_uri_t));
    tx->parsed_uri_incomplete = calloc(1, sizeof (htp_uri_t));

    tx->response_header_lines = cfg->create_list_array(32);
    tx->response_headers = cfg->create_table(32);

    tx->request_protocol_number = -1;

    return tx;
}

/**
 * Destroys the supplied transaction.
 *
 * @param tx
 */
void htp_tx_destroy(htp_tx_t *tx) {
    bstr_free(&tx->request_line);
    bstr_free(&tx->request_line_raw);
    bstr_free(&tx->request_method);
    bstr_free(&tx->request_uri);
    bstr_free(&tx->request_uri_normalized);
    bstr_free(&tx->request_protocol);
    bstr_free(&tx->request_headers_sep);

    if (tx->parsed_uri != NULL) {
        bstr_free(&tx->parsed_uri->scheme);
        bstr_free(&tx->parsed_uri->username);
        bstr_free(&tx->parsed_uri->password);
        bstr_free(&tx->parsed_uri->hostname);
        bstr_free(&tx->parsed_uri->port);
        bstr_free(&tx->parsed_uri->path);
        bstr_free(&tx->parsed_uri->query);
        bstr_free(&tx->parsed_uri->fragment);

        free(tx->parsed_uri);
    }

    if (tx->parsed_uri_incomplete != NULL) {
        bstr_free(&tx->parsed_uri_incomplete->scheme);
        bstr_free(&tx->parsed_uri_incomplete->username);
        bstr_free(&tx->parsed_uri_incomplete->password);
        bstr_free(&tx->parsed_uri_incomplete->hostname);
        bstr_free(&tx->parsed_uri_incomplete->port);
        bstr_free(&tx->parsed_uri_incomplete->path);
        bstr_free(&tx->parsed_uri_incomplete->query);
        bstr_free(&tx->parsed_uri_incomplete->fragment);
        free(tx->parsed_uri_incomplete);
    }

    // Destroy request_header_lines
    htp_header_line_t *hl = NULL;
    list_iterator_reset(tx->request_header_lines);
    while ((hl = list_iterator_next(tx->request_header_lines)) != NULL) {
        bstr_free(&hl->line);
        // No need to destroy hl->header because
        // htp_header_line_t does not own it.
        free(hl);
    }

    list_destroy(&tx->request_header_lines);

    // Destroy request_headers    
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    while (table_iterator_next(tx->request_headers, (void **) & h) != NULL) {
        bstr_free(&h->name);
        bstr_free(&h->value);
        free(h);
    }

    table_destroy(&tx->request_headers);

    if (tx->request_headers_raw != NULL) {
        bstr_free(&tx->request_headers_raw);
    }
    if (tx->response_headers_raw != NULL) {
        bstr_free(&tx->response_headers_raw);
    }

    bstr_free(&tx->response_line);
    bstr_free(&tx->response_line_raw);
    bstr_free(&tx->response_protocol);
    bstr_free(&tx->response_status);
    bstr_free(&tx->response_message);
    bstr_free(&tx->response_headers_sep);

    // Destroy response_header_lines
    hl = NULL;
    list_iterator_reset(tx->response_header_lines);
    while ((hl = list_iterator_next(tx->response_header_lines)) != NULL) {
        bstr_free(&hl->line);
        // No need to destroy hl->header because
        // htp_header_line_t does not own it.
        free(hl);
    }
    list_destroy(&tx->response_header_lines);

    // Destroy response headers    
    h = NULL;
    table_iterator_reset(tx->response_headers);
    while (table_iterator_next(tx->response_headers, (void **) & h) != NULL) {
        bstr_free(&h->name);
        bstr_free(&h->value);
        free(h);
    }
    table_destroy(&tx->response_headers);

    // Tell the connection to remove this transaction
    // from the list
    htp_conn_remove_tx(tx->conn, tx);

    // Invalidate the pointer to this transactions held
    // by the connection parser. This is to allow a transaction
    // to be destroyed from within the final response callback.
    if (tx->connp != NULL) {
        if (tx->connp->out_tx == tx) {
            tx->connp->out_tx = NULL;
        }
    }
    
    bstr_free(&tx->request_content_type);
    bstr_free(&tx->response_content_type);

    htp_urlenp_destroy(&tx->request_urlenp_query);
    htp_urlenp_destroy(&tx->request_urlenp_body);
    htp_mpartp_destroy(&tx->request_mpartp);

    if ((tx->request_params_query_reused == 0)&&(tx->request_params_query != NULL)) {
        bstr *val = NULL;
        table_iterator_reset(tx->request_params_query);
        while(table_iterator_next(tx->request_params_query, (void **) &val) != NULL) {
            bstr_free(&val);
        }
        table_destroy(&tx->request_params_query);
    }

    if ((tx->request_params_body_reused == 0)&&(tx->request_params_body != NULL)) {
        bstr *val = NULL;
        table_iterator_reset(tx->request_params_body);
        while(table_iterator_next(tx->request_params_body, (void **) &val) != NULL) {
            bstr_free(&val);
        }
        table_destroy(&tx->request_params_body);
    }

    if (tx->request_cookies != NULL) {
        bstr *val = NULL;
        table_iterator_reset(tx->request_cookies);
        while(table_iterator_next(tx->request_cookies, (void **) &val) != NULL) {
            bstr_free(&val);
        }
        table_destroy(&tx->request_cookies);
    }

    hook_destroy(tx->hook_request_body_data);

    free(tx);
}

/**
 * Returns the user data associated with this transaction. 
 *
 * @param tx
 * @return A pointer to user data or NULL
 */
void *htp_tx_get_user_data(htp_tx_t *tx) {
    return tx->user_data;
}

/**
 * Sets the configuration that is to be used for this transaction.
 *
 * @param tx
 * @param cfg
 * @param is_cfg_shared
 */
void htp_tx_set_config(htp_tx_t *tx, htp_cfg_t *cfg, int is_cfg_shared) {
    tx->cfg = cfg;
    tx->is_cfg_shared = is_cfg_shared;
}

/**
 * Associates user data with this transaction.
 *
 * @param tx
 * @param user_data
 */
void htp_tx_set_user_data(htp_tx_t *tx, void *user_data) {
    tx->user_data = user_data;
}

/**
 * Register callback for the transaction-specific REQUEST_BODY_DATA hook.
 *
 * @param tx
 * @pram callback_fn
 */
void htp_tx_register_request_body_data(htp_tx_t *tx, int (*callback_fn)(htp_tx_data_t *)) {
    hook_register(&tx->hook_request_body_data, (htp_callback_fn_t)callback_fn);
}

/**
 * Register callback for the transaction-specific RESPONSE_BODY_DATA hook.
 *
 * @param tx
 * @pram callback_fn
 */
void htp_tx_register_response_body_data(htp_tx_t *tx, int (*callback_fn)(htp_tx_data_t *)) {
    hook_register(&tx->hook_response_body_data, (htp_callback_fn_t)callback_fn);
}
