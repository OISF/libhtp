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

void htp_connp_clear_error(htp_connp_t *connp) {
    connp->last_error = NULL;
}

void htp_connp_close(htp_connp_t *connp, const htp_time_t *timestamp) {
    if (connp == NULL) return;
    
    // Close the underlying connection.
    htp_conn_close(connp->conn, timestamp);

    // Update internal flags
    if (connp->in_status != HTP_STREAM_ERROR)
        connp->in_status = HTP_STREAM_CLOSED;
    if (connp->out_status != HTP_STREAM_ERROR)
        connp->out_status = HTP_STREAM_CLOSED;

    // Call the parsers one last time, which will allow them
    // to process the events that depend on stream closure
    htp_connp_req_data(connp, timestamp, NULL, 0);
    htp_connp_res_data(connp, timestamp, NULL, 0);   
}

htp_connp_t *htp_connp_create(htp_cfg_t *cfg) {
    htp_connp_t *connp = calloc(1, sizeof (htp_connp_t));
    if (connp == NULL) return NULL;

    // Use the supplied configuration structure
    connp->cfg = cfg;

    // Create a new connection.
    connp->conn = htp_conn_create();
    if (connp->conn == NULL) {
        free(connp);
        return NULL;
    }

    // Request parsing
    connp->in_state = htp_connp_REQ_IDLE;
    connp->in_status = HTP_STREAM_NEW;

    // Response parsing
    connp->out_state = htp_connp_RES_IDLE; 
    connp->out_status = HTP_STREAM_NEW;

    return connp;
}

void htp_connp_destroy(htp_connp_t *connp) {
    if (connp == NULL) return;
    
    if (connp->in_buf != NULL) {
        free(connp->in_buf);
    }

    if (connp->out_buf != NULL) {
        free(connp->out_buf);
    }

    htp_connp_destroy_decompressors(connp);

    if (connp->put_file != NULL) {
        bstr_free(connp->put_file->filename);
        free(connp->put_file);
    }

    if (connp->in_header) {
        bstr_free(connp->in_header);
        connp->in_header = NULL;
    }
    if (connp->out_header) {
        bstr_free(connp->out_header);
        connp->out_header = NULL;
    }
    free(connp);
}

void htp_connp_destroy_all(htp_connp_t *connp) {
    if (connp == NULL) return;

    // Destroy connection
    htp_conn_destroy(connp->conn);
    connp->conn = NULL;

    // Destroy everything else
    htp_connp_destroy(connp);
}

htp_conn_t *htp_connp_get_connection(const htp_connp_t *connp) {
    if (connp == NULL) return NULL;
    return connp->conn;
}

htp_tx_t *htp_connp_get_in_tx(const htp_connp_t *connp) {
    if (connp == NULL) return NULL;
    return connp->in_tx;
}

htp_log_t *htp_connp_get_last_error(const htp_connp_t *connp) {
    if (connp == NULL) return NULL;
    return connp->last_error;
}

htp_tx_t *htp_connp_get_out_tx(const htp_connp_t *connp) {
    if (connp == NULL) return NULL;
    return connp->out_tx;
}

void *htp_connp_get_user_data(const htp_connp_t *connp) {
    if (connp == NULL) return NULL;
    return (void *)connp->user_data;
}

void htp_connp_in_reset(htp_connp_t *connp) {
    if (connp == NULL) return;
    connp->in_content_length = -1;
    connp->in_body_data_left = -1;
    connp->in_chunk_request_index = connp->in_chunk_count;
}

void htp_connp_open(htp_connp_t *connp, const char *client_addr, int client_port, const char *server_addr,
        int server_port, htp_time_t *timestamp)
{
    if (connp == NULL) return;
    
    // Check connection parser state first.
    if ((connp->in_status != HTP_STREAM_NEW) || (connp->out_status != HTP_STREAM_NEW)) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Connection is already open");
        return;
    }

    if (htp_conn_open(connp->conn, client_addr, client_port, server_addr, server_port, timestamp) != HTP_OK) {
        return;
    }
    
    connp->in_status = HTP_STREAM_OPEN;
    connp->out_status = HTP_STREAM_OPEN;
}

void htp_connp_set_user_data(htp_connp_t *connp, const void *user_data) {
    if (connp == NULL) return;
    connp->user_data = user_data;
}

htp_tx_t *htp_connp_tx_create(htp_connp_t *connp) {
    if (connp == NULL) return NULL;
    
    // Detect pipelining.
    if (htp_list_size(connp->conn->transactions) > connp->out_next_tx_index) {
        connp->conn->flags |= HTP_CONN_PIPELINED;
    }

    htp_tx_t *tx = htp_tx_create(connp);
    if (tx == NULL) return NULL;

    connp->in_tx = tx;   

    htp_connp_in_reset(connp);

    return tx;
}

/**
 * Removes references to the supplied transaction.
 *
 * @param[in] connp
 * @param[in] tx
 */
void htp_connp_tx_remove(htp_connp_t *connp, htp_tx_t *tx) {
    if (connp == NULL) return;

    if (connp->in_tx == tx) {
        connp->in_tx = NULL;
    }

    if (connp->out_tx == tx) {
        connp->out_tx = NULL;
    }
}
