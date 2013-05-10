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

#ifndef HTP_CONNECTION_PARSER_H
#define	HTP_CONNECTION_PARSER_H

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Clears the most recent error, if any.
 *
 * @param[in] connp
 */
void htp_connp_clear_error(htp_connp_t *connp);

/**
 * Closes the connection associated with the supplied parser.
 *
 * @param[in] connp
 * @param[in] timestamp Optional.
 */
void htp_connp_close(htp_connp_t *connp, const htp_time_t *timestamp);

/**
 * Creates a new connection parser using the provided configuration. Because
 * the configuration structure is used directly, in a multithreaded environment
 * you are not allowed to change the structure, ever. If you have a need to
 * change configuration on per-connection basis, make a copy of the configuration
 * structure to go along with every connection parser.
 *
 * @param[in] cfg
 * @return New connection parser instance, or NULL on error.
 */
htp_connp_t *htp_connp_create(htp_cfg_t *cfg);

/**
 * Destroys the connection parser and its data structures, leaving
 * all the data (connection, transactions, etc) intact.
 *
 * @param[in] connp
 */
void htp_connp_destroy(htp_connp_t *connp);

/**
 * Destroys the connection parser, its data structures, as well
 * as the connection and its transactions.
 *
 * @param[in] connp
 */
void htp_connp_destroy_all(htp_connp_t *connp);

/**
 * Returns the connection associated with the connection parser.
 *
 * @param[in] connp
 * @return htp_conn_t instance, or NULL if one is not available.
 */
htp_conn_t *htp_connp_get_connection(const htp_connp_t *connp);

/**
 * Retrieves the pointer to the active inbound transaction. In connection
 * parsing mode there can be many open transactions, and up to 2 active
 * transactions at any one time. This is due to HTTP pipelining. Can be NULL.
 *
 * @param[in] connp
 * @return Active inbound transaction, or NULL if there isn't one.
 */
htp_tx_t *htp_connp_get_in_tx(const htp_connp_t *connp);

/**
 * Returns the last error that occurred with this connection parser. Do note, however,
 * that the value in this field will only be valid immediately after an error condition,
 * but it is not guaranteed to remain valid if the parser is invoked again.
 *
 * @param[in] connp
 * @return A pointer to an htp_log_t instance if there is an error, or NULL
 *         if there isn't.
 */
htp_log_t *htp_connp_get_last_error(const htp_connp_t *connp);

/**
 * Retrieves the pointer to the active outbound transaction. In connection
 * parsing mode there can be many open transactions, and up to 2 active
 * transactions at any one time. This is due to HTTP pipelining. Can be NULL.
 *
 * @param[in] connp
 * @return Active outbound transaction, or NULL if there isn't one.
 */
htp_tx_t *htp_connp_get_out_tx(const htp_connp_t *connp);

/**
 * Retrieve the user data associated with this connection parser.
 *
 * @param[in] connp
 * @return User data, or NULL if there isn't any.
 */
void *htp_connp_get_user_data(const htp_connp_t *connp);

/**
 * Opens connection.
 *
 * @param[in] connp
 * @param[in] client_addr Client address
 * @param[in] client_port Client port
 * @param[in] server_addr Server address
 * @param[in] server_port Server port
 * @param[in] timestamp Optional.
 */
void htp_connp_open(htp_connp_t *connp, const char *client_addr, int client_port, const char *server_addr,
    int server_port, htp_time_t *timestamp);

/**
 * Associate user data with the supplied parser.
 *
 * @param[in] connp
 * @param[in] user_data
 */
void htp_connp_set_user_data(htp_connp_t *connp, const void *user_data);

/**
 *
 * @param[in] connp
 * @param[in] timestamp
 * @param[in] data
 * @param[in] len
 * @return HTP_STREAM_DATA, HTP_STREAM_ERROR or STEAM_STATE_DATA_OTHER (see QUICK_START).
 *         HTP_STREAM_CLOSED and HTP_STREAM_TUNNEL are also possible.
 */
int htp_connp_req_data(htp_connp_t *connp, const htp_time_t *timestamp, const void *data, size_t len);

/**
 * Returns the number of bytes consumed from the most recent inbound data chunk. Normally, an invocation
 * of htp_connp_req_data() will consume all data from the supplied buffer, but there are circumstances
 * where only partial consumption is possible. In such cases HTP_STREAM_DATA_OTHER will be returned.
 * Consumed bytes are no longer necessary, but the remainder of the buffer will be need to be saved
 * for later.
 *
 * @param[in] connp
 * @return The number of bytes consumed from the last data chunk sent for inbound processing.
 */
size_t htp_connp_req_data_consumed(htp_connp_t *connp);

/**
 * Process a chunk of outbound (server or response) data.
 *
 * @param[in] connp
 * @param[in] timestamp Optional.
 * @param[in] data
 * @param[in] len
 * @return HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed
 */
int htp_connp_res_data(htp_connp_t *connp, const htp_time_t *timestamp, const void *data, size_t len);

/**
 * Returns the number of bytes consumed from the most recent outbound data chunk. Normally, an invocation
 * of htp_connp_res_data() will consume all data from the supplied buffer, but there are circumstances
 * where only partial consumption is possible. In such cases HTP_STREAM_DATA_OTHER will be returned.
 * Consumed bytes are no longer necessary, but the remainder of the buffer will be need to be saved
 * for later.
 *
 * @param[in] connp
 * @return The number of bytes consumed from the last data chunk sent for outbound processing.
 */
size_t htp_connp_res_data_consumed(htp_connp_t *connp);

/**
 * Create a new transaction using the connection parser provided.
 *
 * @param[in] connp
 * @return Transaction instance on success, NULL on failure.
 */
htp_tx_t *htp_connp_tx_create(htp_connp_t *connp);

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_CONNECTION_PARSER_H */
