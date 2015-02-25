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

htp_conn_t *htp_conn_create(void) {
    htp_conn_t *conn = calloc(1, sizeof (htp_conn_t));
    if (conn == NULL) return NULL;   

    conn->transactions = htp_list_create(16);
    if (conn->transactions == NULL) {
        free(conn);
        return NULL;
    }

    conn->messages = htp_list_create(8);
    if (conn->messages == NULL) {
        htp_list_destroy(conn->transactions);
        conn->transactions = NULL;
        free(conn);
        return NULL;
    }

    return conn;
}

void htp_conn_close(htp_conn_t *conn, const htp_time_t *timestamp) {
    if (conn == NULL) return;

    // Update timestamp.
    if (timestamp != NULL) {
        memcpy(&(conn->close_timestamp), timestamp, sizeof(htp_time_t));
    }
}

void htp_conn_destroy(htp_conn_t *conn) {
    if (conn == NULL) return;

    if (conn->transactions != NULL) {
        // Destroy individual transactions. Do note that iterating
        // using the iterator does not work here because some of the
        // list element may be NULL (and with the iterator it is impossible
        // to distinguish a NULL element from the end of the list).        
        for (size_t i = 0, n = htp_list_size(conn->transactions); i < n; i++) {
            htp_tx_t *tx = htp_list_get(conn->transactions, i);
            if (tx != NULL) {
                htp_tx_destroy_incomplete(tx);
            }
        }

        htp_list_destroy(conn->transactions);
        conn->transactions = NULL;
    }

    if (conn->messages != NULL) {
        // Destroy individual messages.
        for (size_t i = 0, n = htp_list_size(conn->messages); i < n; i++) {
            htp_log_t *l = htp_list_get(conn->messages, i);
            free((void *) l->msg);
            free(l);
        }

        htp_list_destroy(conn->messages);
        conn->messages = NULL;
    }

    if (conn->server_addr != NULL) {
        free(conn->server_addr);
    }

    if (conn->client_addr != NULL) {
        free(conn->client_addr);
    }
    
    free(conn);
}

htp_status_t htp_conn_open(htp_conn_t *conn, const char *client_addr, int client_port,
        const char *server_addr, int server_port, const htp_time_t *timestamp)
{
    if (conn == NULL) return HTP_ERROR;

    if (client_addr != NULL) {
        conn->client_addr = strdup(client_addr);
        if (conn->client_addr == NULL) return HTP_ERROR;
    }

    conn->client_port = client_port;

    if (server_addr != NULL) {
        conn->server_addr = strdup(server_addr);
        if (conn->server_addr == NULL) {
            if (conn->client_addr != NULL) {
                free(conn->client_addr);
            }

            return HTP_ERROR;
        }
    }

    conn->server_port = server_port;

    // Remember when the connection was opened.
    if (timestamp != NULL) {
        memcpy(&(conn->open_timestamp), timestamp, sizeof(*timestamp));
    }

    return HTP_OK;
}

htp_status_t htp_conn_remove_tx(htp_conn_t *conn, const htp_tx_t *tx) {
    if ((tx == NULL) || (conn == NULL)) return HTP_ERROR;
    if (conn->transactions == NULL) return HTP_ERROR;

    return htp_list_replace(conn->transactions, tx->index, NULL);
}

void htp_conn_track_inbound_data(htp_conn_t *conn, size_t len, const htp_time_t *timestamp) {
    if (conn == NULL) return;
    conn->in_data_counter += len;    
}

void htp_conn_track_outbound_data(htp_conn_t *conn, size_t len, const htp_time_t *timestamp) {
    if (conn == NULL) return;
    conn->out_data_counter += len;    
}
