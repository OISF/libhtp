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
 * Creates a new connection structure.
 *
 * @param connp
 * @return A new htp_connp_t structure on success, NULL on memory allocation failure.
 */
htp_conn_t *htp_conn_create(htp_connp_t *connp) {
    htp_conn_t *conn = calloc(1, sizeof (htp_conn_t));
    if (conn == NULL) return NULL;

    conn->connp = connp;

    conn->transactions = connp->cfg->create_list_array(16);
    if (conn->transactions == NULL) {
        free(conn);
        return NULL;
    }

    conn->messages = connp->cfg->create_list_array(8);
    if (conn->messages == NULL) {
        list_destroy(&conn->transactions);
        free(conn);
        return NULL;
    }

    return conn;
}

/**
 * Destroys a connection, as well as all the transactions it contains. It is
 * not possible to destroy a connection structure yet leave any of its
 * transactions intact. This is because transactions need its connection and
 * connection structures hold little data anyway. The opposite is true, though
 * it is possible to delete a transaction but leave its connection alive.
 *
 * @param conn
 */
void htp_conn_destroy(htp_conn_t *conn) {
    if (conn == NULL) return;
    
    // Destroy individual transactions. Do note that iterating
    // using the iterator does not work here because some of the
    // list element may be NULL (and with the iterator it is impossible
    // to distinguish a NULL element from the end of the list).
    size_t i;
    for (i = 0; i < list_size(conn->transactions); i++) {
        htp_tx_t *tx = (htp_tx_t *)list_get(conn->transactions, i);
        if (tx != NULL) {
            htp_tx_destroy(tx);
        }
    }
    
    list_destroy(&conn->transactions);

    // Destroy individual messages
    htp_log_t *l = NULL;
    list_iterator_reset(conn->messages);
    while ((l = list_iterator_next(conn->messages)) != NULL) {
        free((void *)l->msg);
        free(l);
    }

    list_destroy(&conn->messages);

    if (conn->local_addr != NULL) {
        free(conn->local_addr);
    }

    if (conn->remote_addr != NULL) {
        free(conn->remote_addr);
    }
   
    // Finally, destroy the connection
    // structure itself.
    free(conn);
}

/**
 * Removes the given transaction structure, which makes it possible to
 * safely destroy it. It is safe to destroy transactions in this way
 * because the index of the transactions (in a connection) is preserved.
 *
 * @param conn
 * @param tx
 * @return 1 if transaction was removed or 0 if it wasn't found
 */
int htp_conn_remove_tx(htp_conn_t *conn, htp_tx_t *tx) {
    if ((tx == NULL)||(conn == NULL)) return 0;

    unsigned int i = 0;
    for (i = 0; i < list_size(conn->transactions); i++) {
        htp_tx_t *etx = list_get(conn->transactions, i);
        if (tx == etx) {
            list_replace(conn->transactions, i, NULL);
            return 1;
        }
    }

    return 0;
}
