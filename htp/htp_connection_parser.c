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
 * Clears an existing parser error, if any.
 *
 * @param connp
 */
void htp_connp_clear_error(htp_connp_t *connp) {
    connp->last_error = NULL;
}

/**
 * Closes the connection associated with the supplied parser.
 *
 * @param connp
 * @param timestamp
 */
void htp_connp_close(htp_connp_t *connp, htp_time_t *timestamp) {
    // Update internal information
    if (timestamp)
        memcpy(&connp->conn->close_timestamp, timestamp, sizeof(*timestamp));
    connp->in_status = STREAM_STATE_CLOSED;
    connp->out_status = STREAM_STATE_CLOSED;

    // Call the parsers one last time, which will allow them
    // to process the events that depend on stream closure
    htp_connp_req_data(connp, timestamp, NULL, 0);
    htp_connp_res_data(connp, timestamp, NULL, 0);
}

/**
 * Creates a new connection parser using the provided configuration. Because
 * the configuration structure is used directly, in a multithreaded environment
 * you are not allowed to change the structure, ever. If you have a need to
 * change configuration on per-connection basis, make a copy of the configuration
 * structure to go along with every connection parser.
 *
 * @param cfg
 * @return A pointer to a newly created htp_connp_t instance.
 */
htp_connp_t *htp_connp_create(htp_cfg_t *cfg) {
    htp_connp_t *connp = calloc(1, sizeof (htp_connp_t));
    if (connp == NULL) return NULL;

    // Use the supplied configuration structure
    connp->cfg = cfg;

    // Create a new connection object
    connp->conn = htp_conn_create(connp);
    if (connp->conn == NULL) {
        free(connp);
        return NULL;
    }

    connp->in_status = HTP_OK;

    // Request parsing

    connp->in_line_size = cfg->field_limit_hard;
    connp->in_line_len = 0;
    connp->in_line = malloc(connp->in_line_size);
    if (connp->in_line == NULL) {
        htp_conn_destroy(connp->conn);
        free(connp);
        return NULL;
    }

    connp->in_header_line_index = -1;
    connp->in_state = htp_connp_REQ_IDLE;

    // Response parsing

    connp->out_line_size = cfg->field_limit_hard;
    connp->out_line_len = 0;
    connp->out_line = malloc(connp->out_line_size);
    if (connp->out_line == NULL) {
        free(connp->in_line);
        htp_conn_destroy(connp->conn);
        free(connp);
        return NULL;
    }

    connp->out_header_line_index = -1;
    connp->out_state = htp_connp_RES_IDLE;

    connp->in_status = STREAM_STATE_NEW;
    connp->out_status = STREAM_STATE_NEW;

    return connp;
}

/**
 * Creates a new configuration parser, making a copy of the supplied
 * configuration structure.
 *
 * @param cfg
 * @return A pointer to a newly created htp_connp_t instance.
 */
htp_connp_t *htp_connp_create_copycfg(htp_cfg_t *cfg) {
    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) return NULL;

    connp->cfg = htp_config_copy(cfg);
    connp->is_cfg_private = 1;

    return connp;
}

/**
 * Destroys the connection parser and its data structures, leaving
 * the connection data intact.
 *
 * @param connp
 */
void htp_connp_destroy(htp_connp_t *connp) {
    if (connp->out_decompressor != NULL) {
        connp->out_decompressor->destroy(connp->out_decompressor);
        connp->out_decompressor = NULL;
    }

    if (connp->in_header_line != NULL) {
        if (connp->in_header_line->line != NULL) {
            free(connp->in_header_line->line);
        }

        free(connp->in_header_line);
    }

    free(connp->in_line);

    if (connp->out_header_line != NULL) {
        if (connp->out_header_line->line != NULL) {
            free(connp->out_header_line->line);
        }

        free(connp->out_header_line);
    }

    free(connp->out_line);

    // Destroy the configuration structure, but only
    // if it is our private copy
    if (connp->is_cfg_private) {
        htp_config_destroy(connp->cfg);
    }

    free(connp);
}

/**
 * Destroys the connection parser, its data structures, as well
 * as the connection and its transactions.
 *
 * @param connp
 */
void htp_connp_destroy_all(htp_connp_t *connp) {
    if (connp->conn == NULL) {
        fprintf(stderr, "HTP: htp_connp_destroy_all was invoked, but conn is NULL\n");
        return;
    }

    // Destroy connection
    htp_conn_destroy(connp->conn);
    connp->conn = NULL;

    // Destroy everything else
    htp_connp_destroy(connp);
}

/**
 * Retrieve the user data associated with this connection parser.
 * 
 * @param connp
 * @return User data, or NULL if there isn't any.
 */
void *htp_connp_get_user_data(htp_connp_t *connp) {
    return connp->user_data;
}

/**
 * Returns the last error that occurred with this connection parser. Do note, however,
 * that the value in this field will only be valid immediately after an error condition,
 * but it is not guaranteed to remain valid if the parser is invoked again.
 *
 * @param connp
 * @return A pointer to an htp_log_t instance if there is an error, or NULL
 *         if there isn't.
 */
htp_log_t *htp_connp_get_last_error(htp_connp_t *connp) {
    return connp->last_error;
}

/**
 * Opens connection.
 *
 * @param connp
 * @param remote_addr Remote address
 * @param remote_port Remote port
 * @param local_addr Local address
 * @param local_port Local port
 * @param timestamp
 */
void htp_connp_open(htp_connp_t *connp, const char *remote_addr, int remote_port, const char *local_addr, int local_port, htp_time_t *timestamp) {
    if ((connp->in_status != STREAM_STATE_NEW) || (connp->out_status != STREAM_STATE_NEW)) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Connection is already open");
        return;
    }

    if (remote_addr != NULL) {
        connp->conn->remote_addr = strdup(remote_addr);
        if (connp->conn->remote_addr == NULL) return;
    }

    connp->conn->remote_port = remote_port;

    if (local_addr != NULL) {
        connp->conn->local_addr = strdup(local_addr);
        if (connp->conn->local_addr == NULL) {
            if (connp->conn->remote_addr != NULL) {
                free(connp->conn->remote_addr);
            }
            return;
        }
    }

    connp->conn->local_port = local_port;
    if (timestamp)
        memcpy(&connp->conn->open_timestamp, timestamp, sizeof(*timestamp));
    connp->in_status = STREAM_STATE_OPEN;
    connp->out_status = STREAM_STATE_OPEN;
}

/**
 * Associate user data with the supplied parser.
 *
 * @param connp
 * @param user_data
 */
void htp_connp_set_user_data(htp_connp_t *connp, void *user_data) {
    connp->user_data = user_data;
}
