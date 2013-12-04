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

#ifndef HTP_CONNECTION_H
#define	HTP_CONNECTION_H

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Creates a new connection structure.
 * 
 * @return A new connection structure on success, NULL on memory allocation failure.
 */
htp_conn_t *htp_conn_create(void);

/**
 * Closes the connection.
 *
 * @param[in] conn
 * @param[in] timestamp
 */
void htp_conn_close(htp_conn_t *conn, const struct timeval *timestamp);

/**
 * Destroys a connection, as well as all the transactions it contains. It is
 * not possible to destroy a connection structure yet leave any of its
 * transactions intact. This is because transactions need its connection and
 * connection structures hold little data anyway. The opposite is true, though
 * it is possible to delete a transaction but leave its connection alive.
 *
 * @param[in] conn
 */
void htp_conn_destroy(htp_conn_t *conn);

/**
 * Opens a connection. This function will essentially only store the provided data
 * for future reference. The timestamp parameter is optional.
 * 
 * @param[in] conn
 * @param[in] remote_addr
 * @param[in] remote_port
 * @param[in] local_addr
 * @param[in] local_port
 * @param[in] timestamp
 * @return
 */
htp_status_t htp_conn_open(htp_conn_t *conn, const char *remote_addr, int remote_port,
    const char *local_addr, int local_port, const struct timeval *timestamp);

/**
 * Removes the given transaction structure, which makes it possible to
 * safely destroy it. It is safe to destroy transactions in this way
 * because the index of the transactions (in a connection) is preserved.
 *
 * @param[in] conn
 * @param[in] tx
 * @return HTP_OK if transaction was removed (replaced with NULL) or HTP_ERROR if it wasn't found.
 */
htp_status_t htp_conn_remove_tx(htp_conn_t *conn, const htp_tx_t *tx);

/**
 * Keeps track of inbound packets and data.
 *
 * @param[in] conn
 * @param[in] len
 * @param[in] timestamp
 */
void htp_conn_track_inbound_data(htp_conn_t *conn, size_t len, const struct timeval *timestamp);

/**
 * Keeps track of outbound packets and data.
 * 
 * @param[in] conn
 * @param[in] len
 * @param[in] timestamp
 */
void htp_conn_track_outbound_data(htp_conn_t *conn, size_t len, const struct timeval *timestamp);

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_CONNECTION_H */

