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

#define IN_TEST_NEXT_BYTE_OR_RETURN(X) \
if ((X)->in_current_read_offset >= (X)->in_current_len) { \
    return HTP_DATA; \
}

#define IN_PEEK_NEXT(X) \
if ((X)->in_current_read_offset >= (X)->in_current_len) { \
    (X)->in_next_byte = -1; \
} else { \
    (X)->in_next_byte = (X)->in_current_data[(X)->in_current_read_offset]; \
}

#define IN_NEXT_BYTE(X) \
if ((X)->in_current_read_offset < (X)->in_current_len) { \
    (X)->in_next_byte = (X)->in_current_data[(X)->in_current_read_offset]; \
    (X)->in_current_read_offset++; \
    (X)->in_current_consume_offset++; \
    (X)->in_stream_offset++; \
} else { \
    (X)->in_next_byte = -1; \
}

#define IN_NEXT_BYTE_OR_RETURN(X) \
if ((X)->in_current_read_offset < (X)->in_current_len) { \
    (X)->in_next_byte = (X)->in_current_data[(X)->in_current_read_offset]; \
    (X)->in_current_read_offset++; \
    (X)->in_current_consume_offset++; \
    (X)->in_stream_offset++; \
} else { \
    return HTP_DATA; \
}

#define IN_COPY_BYTE_OR_RETURN(X) \
if ((X)->in_current_read_offset < (X)->in_current_len) { \
    (X)->in_next_byte = (X)->in_current_data[(X)->in_current_read_offset]; \
    (X)->in_current_read_offset++; \
    (X)->in_stream_offset++; \
} else { \
    return HTP_DATA_BUFFER; \
}

/**
 * Sends outstanding connection data to the currently active data receiver hook.
 *
 * @param[in] connp
 * @param[in] is_last
 * @return HTP_OK, or a value returned from a callback.
 */
static htp_status_t htp_connp_req_receiver_send_data(htp_connp_t *connp, int is_last) {
    if (connp->in_data_receiver_hook == NULL) return HTP_OK;

    htp_tx_data_t d;
    d.tx = connp->in_tx;
    d.data = connp->in_current_data + connp->in_current_receiver_offset;
    d.len = connp->in_current_read_offset - connp->in_current_receiver_offset;
    d.is_last = is_last;

    htp_status_t rc = htp_hook_run_all(connp->in_data_receiver_hook, &d);
    if (rc != HTP_OK) return rc;

    connp->in_current_receiver_offset = connp->in_current_read_offset;

    return HTP_OK;
}

/**
 * Configures the data receiver hook. If there is a previous hook, it will be finalized and cleared.
 *
 * @param[in] connp
 * @param[in] data_receiver_hook
 * @return HTP_OK, or a value returned from a callback.
 */
static htp_status_t htp_connp_req_receiver_set(htp_connp_t *connp, htp_hook_t *data_receiver_hook) {
    htp_connp_req_receiver_finalize_clear(connp);

    connp->in_data_receiver_hook = data_receiver_hook;
    connp->in_current_receiver_offset = connp->in_current_read_offset;

    return HTP_OK;
}

/**
 * Finalizes an existing data receiver hook by sending any outstanding data to it. The
 * hook is then removed so that it receives no more data.
 *
 * @param[in] connp
 * @return HTP_OK, or a value returned from a callback.
 */
htp_status_t htp_connp_req_receiver_finalize_clear(htp_connp_t *connp) {
    if (connp->in_data_receiver_hook == NULL) return HTP_OK;

    htp_status_t rc = htp_connp_req_receiver_send_data(connp, 1 /* last */);

    connp->in_data_receiver_hook = NULL;

    return rc;
}

/**
 * Handles request parser state changes. At the moment, this function is used only
 * to configure data receivers, which are sent raw connection data.
 *
 * @param[in] connp
 * @return HTP_OK, or a value returned from a callback.
 */
static htp_status_t htp_req_handle_state_change(htp_connp_t *connp) {
    if (connp->in_state_previous == connp->in_state) return HTP_OK;

    if (connp->in_state == htp_connp_REQ_HEADERS) {
        htp_status_t rc = HTP_OK;

        switch (connp->in_tx->request_progress) {
            case HTP_REQUEST_HEADERS:
                rc = htp_connp_req_receiver_set(connp, connp->in_tx->cfg->hook_request_header_data);
                break;

            case HTP_REQUEST_TRAILER:
                rc = htp_connp_req_receiver_set(connp, connp->in_tx->cfg->hook_request_trailer_data);
                break;

            default:
                // Do nothing; receivers are currently used only for header blocks.
                break;
        }

        if (rc != HTP_OK) return rc;
    }

    // Initially, I had the finalization of raw data sending here, but that
    // caused the last REQUEST_HEADER_DATA hook to be invoked after the
    // REQUEST_HEADERS hook -- which I thought made no sense. For that reason,
    // the finalization is now initiated from the request header processing code,
    // which is less elegant but provides a better user experience. Having some
    // (or all) hooks to be invoked on state change might work better.

    connp->in_state_previous = connp->in_state;

    return HTP_OK;
}

/**
 * If there is any data left in the inbound data chunk, this function will preserve
 * it for later consumption. The maximum amount accepted for buffering is controlled
 * by htp_config_t::field_limit_hard.
 *
 * @param[in] connp
 * @return HTP_OK, or HTP_ERROR on fatal failure.
 */
static htp_status_t htp_connp_req_buffer(htp_connp_t *connp) {
    if (connp->in_current_data == NULL) return HTP_OK;

    unsigned char *data = connp->in_current_data + connp->in_current_consume_offset;
    size_t len = connp->in_current_read_offset - connp->in_current_consume_offset;

    if (len == 0)
        return HTP_OK;

    // Check the hard (buffering) limit.
   
    size_t newlen = connp->in_buf_size + len;

    // When calculating the size of the buffer, take into account the
    // space we're using for the request header buffer.
    if (connp->in_header != NULL) {
        newlen += bstr_len(connp->in_header);
    }

    if (newlen > connp->in_tx->cfg->field_limit_hard) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Request buffer over the limit: size %zd limit %zd.",
                newlen, connp->in_tx->cfg->field_limit_hard);        
        return HTP_ERROR;
    }

    // Copy the data remaining in the buffer.

    if (connp->in_buf == NULL) {
        connp->in_buf = malloc(len);
        if (connp->in_buf == NULL) return HTP_ERROR;
        memcpy(connp->in_buf, data, len);
        connp->in_buf_size = len;
    } else {
        size_t newsize = connp->in_buf_size + len;
        unsigned char *newbuf = realloc(connp->in_buf, newsize);
        if (newbuf == NULL) return HTP_ERROR;
        connp->in_buf = newbuf;
        memcpy(connp->in_buf + connp->in_buf_size, data, len);
        connp->in_buf_size = newsize;
    }

    // Reset the consumer position.
    connp->in_current_consume_offset = connp->in_current_read_offset;

    return HTP_OK;
}

/**
 * Returns to the caller the memory region that should be processed next. This function
 * hides away the buffering process from the rest of the code, allowing it to work with
 * non-buffered data that's in the inbound chunk, or buffered data that's in our structures.
 *
 * @param[in] connp
 * @param[out] data
 * @param[out] len
 * @return HTP_OK
 */
static htp_status_t htp_connp_req_consolidate_data(htp_connp_t *connp, unsigned char **data, size_t *len) {
    if (connp->in_buf == NULL) {
        // We do not have any data buffered; point to the current data chunk.
        *data = connp->in_current_data + connp->in_current_consume_offset;
        *len = connp->in_current_read_offset - connp->in_current_consume_offset;
    } else {
        // We already have some data in the buffer. Add the data from the current
        // chunk to it, and point to the consolidated buffer.
        if (htp_connp_req_buffer(connp) != HTP_OK) {
            return HTP_ERROR;
        }

        *data = connp->in_buf;
        *len = connp->in_buf_size;
    }

    return HTP_OK;
}

/**
 * Clears buffered inbound data and resets the consumer position to the reader position.
 *
 * @param[in] connp
 */
static void htp_connp_req_clear_buffer(htp_connp_t *connp) {
    connp->in_current_consume_offset = connp->in_current_read_offset;

    if (connp->in_buf != NULL) {
        free(connp->in_buf);
        connp->in_buf = NULL;
        connp->in_buf_size = 0;
    }
}

/**
 * Performs a check for a CONNECT transaction to decide whether inbound
 * parsing needs to be suspended.
 *
 * @param[in] connp
 * @return HTP_OK if the request does not use CONNECT, HTP_DATA_OTHER if
 *          inbound parsing needs to be suspended until we hear from the
 *          other side
 */
htp_status_t htp_connp_REQ_CONNECT_CHECK(htp_connp_t *connp) {
    // If the request uses the CONNECT method, then there will
    // not be a request body, but first we need to wait to see the
    // response in order to determine if the tunneling request
    // was a success.
    if (connp->in_tx->request_method_number == HTP_M_CONNECT) {        
        connp->in_state = htp_connp_REQ_CONNECT_WAIT_RESPONSE;
        connp->in_status = HTP_STREAM_DATA_OTHER;
        return HTP_DATA_OTHER;
    }

    // Continue to the next step to determine 
    // the presence of request body
    connp->in_state = htp_connp_REQ_BODY_DETERMINE;

    return HTP_OK;
}

/**
 * Determines whether inbound parsing needs to continue or stop. In
 * case the data appears to be plain text HTTP, we try to continue.
 *
 * @param[in] connp
 * @return HTP_OK if the parser can resume parsing, HTP_DATA_BUFFER if
 *         we need more data.
 */
htp_status_t htp_connp_REQ_CONNECT_PROBE_DATA(htp_connp_t *connp) {
    for (;;) {//;i < max_read; i++) {
        IN_PEEK_NEXT(connp);
        // Have we reached the end of the line? For some reason
        // we can't test after IN_COPY_BYTE_OR_RETURN */
        if (connp->in_next_byte == LF || connp->in_next_byte == 0x00)
            break;

        IN_COPY_BYTE_OR_RETURN(connp);

    }

    unsigned char *data;
    size_t len;
    if (htp_connp_req_consolidate_data(connp, &data, &len) != HTP_OK) {
        fprintf(stderr, "htp_connp_req_consolidate_data fail");
        return HTP_ERROR;
    }
#ifdef HTP_DEBUG
    fprint_raw_data(stderr, "PROBING", data, len);
#endif

    size_t pos = 0;
    size_t mstart = 0;
    // skip past leading whitespace. IIS allows this
    while ((pos < len) && htp_is_space(data[pos]))
        pos++;
    if (pos)
        mstart = pos;
    // The request method starts at the beginning of the
    // line and ends with the first whitespace character.
    while ((pos < len) && (!htp_is_space(data[pos])))
        pos++;

    int methodi = HTP_M_UNKNOWN;
    bstr *method = bstr_dup_mem(data + mstart, pos - mstart);
    if (method) {
        methodi = htp_convert_method_to_number(method);
        bstr_free(method);
    }
    if (methodi != HTP_M_UNKNOWN) {
#ifdef HTP_DEBUG
        fprint_raw_data(stderr, "htp_connp_REQ_CONNECT_PROBE_DATA: tunnel contains plain text HTTP", data, len);
#endif
        connp->in_state = htp_connp_REQ_FINALIZE;
    } else {
#ifdef HTP_DEBUG
        fprint_raw_data(stderr, "htp_connp_REQ_CONNECT_PROBE_DATA: tunnel is not HTTP", data, len);
#endif
        connp->in_status = HTP_STREAM_TUNNEL;
        connp->out_status = HTP_STREAM_TUNNEL;
    }

    // not calling htp_connp_req_clear_buffer, we're not consuming the data

    return HTP_OK;
}

/**
 * Determines whether inbound parsing, which was suspended after
 * encountering a CONNECT transaction, can proceed (after receiving
 * the response).
 *
 * @param[in] connp
 * @return HTP_OK if the parser can resume parsing, HTP_DATA_OTHER if
 *         it needs to continue waiting.
 */
htp_status_t htp_connp_REQ_CONNECT_WAIT_RESPONSE(htp_connp_t *connp) {
    // Check that we saw the response line of the current inbound transaction.
    if (connp->in_tx->response_progress <= HTP_RESPONSE_LINE) {
        return HTP_DATA_OTHER;
    }

    // A 2xx response means a tunnel was established. Anything
    // else means we continue to follow the HTTP stream.
    if ((connp->in_tx->response_status_number >= 200) && (connp->in_tx->response_status_number <= 299)) {
        // TODO Check that the server did not accept a connection to itself.

        // The requested tunnel was established: we are going
        // to probe the remaining data on this stream to see
        // if we need to ignore it or parse it
        connp->in_state = htp_connp_REQ_CONNECT_PROBE_DATA;
    } else {
        // No tunnel; continue to the next transaction
        connp->in_state = htp_connp_REQ_FINALIZE;
    }

    return HTP_OK;
}

/**
 * Consumes bytes until the end of the current line.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_BODY_CHUNKED_DATA_END(htp_connp_t *connp) {
    // TODO We shouldn't really see anything apart from CR and LF,
    //      so we should warn about anything else.

    for (;;) {
        IN_NEXT_BYTE_OR_RETURN(connp);

        connp->in_tx->request_message_len++;

        if (connp->in_next_byte == LF) {
            connp->in_state = htp_connp_REQ_BODY_CHUNKED_LENGTH;
            return HTP_OK;
        }
    }

    return HTP_ERROR;
}

/**
 * Processes a chunk of data.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_BODY_CHUNKED_DATA(htp_connp_t *connp) {
    // Determine how many bytes we can consume.
    size_t bytes_to_consume;
    if (connp->in_current_len - connp->in_current_read_offset >= connp->in_chunked_length) {
        // Entire chunk available in the buffer; read all of it.
        bytes_to_consume = connp->in_chunked_length;
    } else {
        // Partial chunk available in the buffer; read as much as we can.
        bytes_to_consume = connp->in_current_len - connp->in_current_read_offset;
    }

    #ifdef HTP_DEBUG
    fprintf(stderr, "htp_connp_REQ_BODY_CHUNKED_DATA Consuming %zd bytes\n", bytes_to_consume);
    #endif

    // If the input buffer is empty, ask for more data.
    if (bytes_to_consume == 0) return HTP_DATA;

    // Consume the data.
    htp_status_t rc = htp_tx_req_process_body_data_ex(connp->in_tx, connp->in_current_data + connp->in_current_read_offset, bytes_to_consume);
    if (rc != HTP_OK) return rc;

    // Adjust counters.
    connp->in_current_read_offset += bytes_to_consume;
    connp->in_current_consume_offset += bytes_to_consume;
    connp->in_stream_offset += bytes_to_consume;
    connp->in_tx->request_message_len += bytes_to_consume;
    connp->in_chunked_length -= bytes_to_consume;

    if (connp->in_chunked_length == 0) {
        // End of the chunk.
        connp->in_state = htp_connp_REQ_BODY_CHUNKED_DATA_END;
        return HTP_OK;
    }

    // Ask for more data.
    return HTP_DATA;
}

/**
 * Extracts chunk length.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_BODY_CHUNKED_LENGTH(htp_connp_t *connp) {
    for (;;) {
        IN_COPY_BYTE_OR_RETURN(connp);

        // Have we reached the end of the line?
        if (connp->in_next_byte == LF) {
            unsigned char *data;
            size_t len;

            if (htp_connp_req_consolidate_data(connp, &data, &len) != HTP_OK) {
                return HTP_ERROR;
            }

            connp->in_tx->request_message_len += len;

            #ifdef HTP_DEBUG
            fprint_raw_data(stderr, "Chunk length line", data, len);
            #endif

            htp_chomp(data, &len);

            connp->in_chunked_length = htp_parse_chunked_length(data, len);

            htp_connp_req_clear_buffer(connp);

            // Handle chunk length.
            if (connp->in_chunked_length > 0) {
                // More data available.                
                connp->in_state = htp_connp_REQ_BODY_CHUNKED_DATA;
            } else if (connp->in_chunked_length == 0) {
                // End of data.
                connp->in_state = htp_connp_REQ_HEADERS;
                connp->in_tx->request_progress = HTP_REQUEST_TRAILER;
            } else {
                // Invalid chunk length.
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Request chunk encoding: Invalid chunk length");
                return HTP_ERROR;
            }

            return HTP_OK;
        }
    }

    return HTP_ERROR;
}

/**
 * Processes identity request body.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_BODY_IDENTITY(htp_connp_t *connp) {
    // Determine how many bytes we can consume.
    size_t bytes_to_consume;
    if (connp->in_current_len - connp->in_current_read_offset >= connp->in_body_data_left) {
        bytes_to_consume = connp->in_body_data_left;
    } else {
        bytes_to_consume = connp->in_current_len - connp->in_current_read_offset;
    }

    // If the input buffer is empty, ask for more data.
    if (bytes_to_consume == 0) return HTP_DATA;

    // Consume data.
    int rc = htp_tx_req_process_body_data_ex(connp->in_tx, connp->in_current_data + connp->in_current_read_offset, bytes_to_consume);
    if (rc != HTP_OK) return rc;

    // Adjust counters.
    connp->in_current_read_offset += bytes_to_consume;
    connp->in_current_consume_offset += bytes_to_consume;
    connp->in_stream_offset += bytes_to_consume;
    connp->in_tx->request_message_len += bytes_to_consume;
    connp->in_body_data_left -= bytes_to_consume;

    if (connp->in_body_data_left == 0) {
        // End of request body.
        connp->in_state = htp_connp_REQ_FINALIZE;
        return HTP_OK;
    }

    // Ask for more data.
    return HTP_DATA;
}

/**
 * Determines presence (and encoding) of a request body.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_BODY_DETERMINE(htp_connp_t *connp) {
    // Determine the next state based on the presence of the request
    // body, and the coding used.
    switch (connp->in_tx->request_transfer_coding) {

        case HTP_CODING_CHUNKED:
            connp->in_state = htp_connp_REQ_BODY_CHUNKED_LENGTH;
            connp->in_tx->request_progress = HTP_REQUEST_BODY;
            break;

        case HTP_CODING_IDENTITY:
            connp->in_content_length = connp->in_tx->request_content_length;
            connp->in_body_data_left = connp->in_content_length;

            if (connp->in_content_length != 0) {
                connp->in_state = htp_connp_REQ_BODY_IDENTITY;
                connp->in_tx->request_progress = HTP_REQUEST_BODY;
            } else {
                connp->in_tx->connp->in_state = htp_connp_REQ_FINALIZE;
            }
            break;

        case HTP_CODING_NO_BODY:
            // This request does not have a body, which
            // means that we're done with it
            connp->in_state = htp_connp_REQ_FINALIZE;
            break;

        default:
            // Should not be here
            return HTP_ERROR;
            break;
    }

    return HTP_OK;
}

/**
 * Parses request headers.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_HEADERS(htp_connp_t *connp) {
    for (;;) {
        IN_COPY_BYTE_OR_RETURN(connp);

        // Have we reached the end of the line?
        if (connp->in_next_byte == LF) {
            unsigned char *data;
            size_t len;

            if (htp_connp_req_consolidate_data(connp, &data, &len) != HTP_OK) {
                return HTP_ERROR;
            }

            #ifdef HTP_DEBUG
            fprint_raw_data(stderr, __func__, data, len);
            #endif           

            // Should we terminate headers?
            if (htp_connp_is_line_terminator(connp, data, len)) {
                // Parse previous header, if any.
                if (connp->in_header != NULL) {
                    if (connp->cfg->process_request_header(connp, bstr_ptr(connp->in_header),
                            bstr_len(connp->in_header)) != HTP_OK) return HTP_ERROR;

                    bstr_free(connp->in_header);
                    connp->in_header = NULL;
                }

                htp_connp_req_clear_buffer(connp);

                // We've seen all the request headers.
                return htp_tx_state_request_headers(connp->in_tx);
            }

            htp_chomp(data, &len);

            // Check for header folding.
            if (htp_connp_is_line_folded(data, len) == 0) {
                // New header line.

                // Parse previous header, if any.
                if (connp->in_header != NULL) {
                    if (connp->cfg->process_request_header(connp, bstr_ptr(connp->in_header),
                            bstr_len(connp->in_header)) != HTP_OK) return HTP_ERROR;

                    bstr_free(connp->in_header);
                    connp->in_header = NULL;
                }

                IN_PEEK_NEXT(connp);

                if (connp->in_next_byte != -1 && htp_is_folding_char(connp->in_next_byte) == 0) {
                    // Because we know this header is not folded, we can process the buffer straight away.
                    if (connp->cfg->process_request_header(connp, data, len) != HTP_OK) return HTP_ERROR;
                } else {
                    // Keep the partial header data for parsing later.
                    connp->in_header = bstr_dup_mem(data, len);
                    if (connp->in_header == NULL) return HTP_ERROR;
                }
            } else {
                // Folding; check that there's a previous header line to add to.
                if (connp->in_header == NULL) {
                    // Invalid folding.

                    // Warn only once per transaction.
                    if (!(connp->in_tx->flags & HTP_INVALID_FOLDING)) {
                        connp->in_tx->flags |= HTP_INVALID_FOLDING;
                        htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Invalid request field folding");
                    }

                    // Keep the header data for parsing later.
                    connp->in_header = bstr_dup_mem(data, len);
                    if (connp->in_header == NULL) return HTP_ERROR;
                } else {
                    // Add to the existing header.                    
                    bstr *new_in_header = bstr_add_mem(connp->in_header, data, len);
                    if (new_in_header == NULL) return HTP_ERROR;
                    connp->in_header = new_in_header;
                }
            }

            htp_connp_req_clear_buffer(connp);
        }
    }

    return HTP_ERROR;
}

/**
 * Determines request protocol.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_PROTOCOL(htp_connp_t *connp) {
    // Is this a short-style HTTP/0.9 request? If it is,
    // we will not want to parse request headers.
    if (connp->in_tx->is_protocol_0_9 == 0) {
        // Switch to request header parsing.
        connp->in_state = htp_connp_REQ_HEADERS;
        connp->in_tx->request_progress = HTP_REQUEST_HEADERS;
    } else {
        // We're done with this request.
        connp->in_state = htp_connp_REQ_FINALIZE;
    }

    return HTP_OK;
}

/**
 * Parse the request line.
 *
 * @param[in] connp
 * @returns HTP_OK on succesful parse, HTP_ERROR on error.
 */
htp_status_t htp_connp_REQ_LINE_complete(htp_connp_t *connp) {
    unsigned char *data;
    size_t len;

    if (htp_connp_req_consolidate_data(connp, &data, &len) != HTP_OK) {
        return HTP_ERROR;
    }

    #ifdef HTP_DEBUG
    fprint_raw_data(stderr, __func__, data, len);
    #endif

    // Is this a line that should be ignored?
    if (htp_connp_is_line_ignorable(connp, data, len)) {
        // We have an empty/whitespace line, which we'll note, ignore and move on.
        connp->in_tx->request_ignored_lines++;

        htp_connp_req_clear_buffer(connp);

        return HTP_OK;
    }

    // Process request line.

    htp_chomp(data, &len);

    connp->in_tx->request_line = bstr_dup_mem(data, len);
    if (connp->in_tx->request_line == NULL)
        return HTP_ERROR;

    if (connp->cfg->parse_request_line(connp) != HTP_OK)
        return HTP_ERROR;

    // Finalize request line parsing.

    if (htp_tx_state_request_line(connp->in_tx) != HTP_OK)
        return HTP_ERROR;

    htp_connp_req_clear_buffer(connp);

    return HTP_OK;
}

/**
 * Parses request line.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_LINE(htp_connp_t *connp) {
    for (;;) {
        // Get one byte
        IN_COPY_BYTE_OR_RETURN(connp);

        // Have we reached the end of the line?
        if (connp->in_next_byte == LF) {
            return htp_connp_REQ_LINE_complete(connp);
        }
    }

    return HTP_ERROR;
}

htp_status_t htp_connp_REQ_FINALIZE(htp_connp_t *connp) {
    return htp_tx_state_request_complete(connp->in_tx);
}

htp_status_t htp_connp_REQ_IGNORE_DATA_AFTER_HTTP_0_9(htp_connp_t *connp) {
    // Consume whatever is left in the buffer.

    size_t bytes_left = connp->in_current_len - connp->in_current_read_offset;

    if (bytes_left > 0) {
        connp->conn->flags |= HTP_CONN_HTTP_0_9_EXTRA;
    }

    connp->in_current_read_offset += bytes_left;
    connp->in_current_consume_offset += bytes_left;
    connp->in_stream_offset += bytes_left;

    return HTP_DATA;
}

/**
 * The idle state is where the parser will end up after a transaction is processed.
 * If there is more data available, a new request will be started.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_REQ_IDLE(htp_connp_t * connp) {
    // We want to start parsing the next request (and change
    // the state from IDLE) only if there's at least one
    // byte of data available. Otherwise we could be creating
    // new structures even if there's no more data on the
    // connection.
    IN_TEST_NEXT_BYTE_OR_RETURN(connp);

    connp->in_tx = htp_connp_tx_create(connp);
    if (connp->in_tx == NULL) return HTP_ERROR;

    // Change state to TRANSACTION_START
    htp_tx_state_request_start(connp->in_tx);

    return HTP_OK;
}

/**
 * Returns how many bytes from the current data chunks were consumed so far.
 *
 * @param[in] connp
 * @return The number of bytes consumed.
 */
size_t htp_connp_req_data_consumed(htp_connp_t *connp) {
    return connp->in_current_read_offset;
}

int htp_connp_req_data(htp_connp_t *connp, const htp_time_t *timestamp, const void *data, size_t len) {
    #ifdef HTP_DEBUG
    fprintf(stderr, "htp_connp_req_data(connp->in_status %x)\n", connp->in_status);
    fprint_raw_data(stderr, __func__, data, len);
    #endif

    // Return if the connection is in stop state.
    if (connp->in_status == HTP_STREAM_STOP) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_INFO, 0, "Inbound parser is in HTP_STREAM_STOP");
        return HTP_STREAM_STOP;
    }

    // Return if the connection had a fatal error earlier
    if (connp->in_status == HTP_STREAM_ERROR) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Inbound parser is in HTP_STREAM_ERROR");

        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_DATA (previous error)\n");
        #endif

        return HTP_STREAM_ERROR;
    }

    // Sanity check: we must have a transaction pointer if the state is not IDLE (no inbound transaction)
    if ((connp->in_tx == NULL)&&(connp->in_state != htp_connp_REQ_IDLE)) {
        connp->in_status = HTP_STREAM_ERROR;

        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Missing inbound transaction data");

        return HTP_STREAM_ERROR;
    }

    // If the length of the supplied data chunk is zero, proceed
    // only if the stream has been closed. We do not allow zero-sized
    // chunks in the API, but we use them internally to force the parsers
    // to finalize parsing.
    if (((data == NULL) || (len == 0)) && (connp->in_status != HTP_STREAM_CLOSED)) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Zero-length data chunks are not allowed");

        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_DATA (zero-length chunk)\n");
        #endif

        return HTP_STREAM_CLOSED;
    }

    // Remember the timestamp of the current request data chunk
    if (timestamp != NULL) {
        memcpy(&connp->in_timestamp, timestamp, sizeof (*timestamp));
    }

    // Store the current chunk information    
    connp->in_current_data = (unsigned char *) data;
    connp->in_current_len = len;
    connp->in_current_read_offset = 0;
    connp->in_current_consume_offset = 0;
    connp->in_current_receiver_offset = 0;
    connp->in_chunk_count++;

    htp_conn_track_inbound_data(connp->conn, len, timestamp);


    // Return without processing any data if the stream is in tunneling
    // mode (which it would be after an initial CONNECT transaction).
    if (connp->in_status == HTP_STREAM_TUNNEL) {
        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_TUNNEL\n");
        #endif

        return HTP_STREAM_TUNNEL;
    }

    if (connp->out_status == HTP_STREAM_DATA_OTHER) {
        connp->out_status = HTP_STREAM_DATA;
    }

    // Invoke a processor, in a loop, until an error
    // occurs or until we run out of data. Many processors
    // will process a request, each pointing to the next
    // processor that needs to run.
    for (;;) {
        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_connp_req_data: in state=%s, progress=%s\n",
                htp_connp_in_state_as_string(connp),
                htp_tx_request_progress_as_string(connp->in_tx));
        #endif

        // Return if there's been an error or if we've run out of data. We are relying
        // on processors to supply error messages, so we'll keep quiet here.
        htp_status_t rc = connp->in_state(connp);
        if (rc == HTP_OK) {
            if (connp->in_status == HTP_STREAM_TUNNEL) {
                #ifdef HTP_DEBUG
                fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_TUNNEL\n");
                #endif

                return HTP_STREAM_TUNNEL;
            }

            rc = htp_req_handle_state_change(connp);
        }

        if (rc != HTP_OK) {
            // Do we need more data?
            if ((rc == HTP_DATA) || (rc == HTP_DATA_BUFFER)) {
                htp_connp_req_receiver_send_data(connp, 0 /* not last */);

                if (rc == HTP_DATA_BUFFER) {
                    if (htp_connp_req_buffer(connp) != HTP_OK) {
                        connp->in_status = HTP_STREAM_ERROR;
                        return HTP_STREAM_ERROR;
                    }
                }

                #ifdef HTP_DEBUG
                fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_DATA\n");
                #endif

                connp->in_status = HTP_STREAM_DATA;

                return HTP_STREAM_DATA;
            }

            // Check for suspended parsing.
            if (rc == HTP_DATA_OTHER) {
                // We might have actually consumed the entire data chunk?
                if (connp->in_current_read_offset >= connp->in_current_len) {
                    // Do not send STREAM_DATE_DATA_OTHER if we've consumed the entire chunk.

                    #ifdef HTP_DEBUG
                    fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_DATA (suspended parsing)\n");
                    #endif

                    connp->in_status = HTP_STREAM_DATA;

                    return HTP_STREAM_DATA;
                } else {
                    // Partial chunk consumption.

                    #ifdef HTP_DEBUG
                    fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_DATA_OTHER\n");
                    #endif

                    connp->in_status = HTP_STREAM_DATA_OTHER;

                    return HTP_STREAM_DATA_OTHER;
                }
            }

            // Check for the stop signal.
            if (rc == HTP_STOP) {
                #ifdef HTP_DEBUG
                fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_STOP\n");
                #endif

                connp->in_status = HTP_STREAM_STOP;

                return HTP_STREAM_STOP;
            }

            #ifdef HTP_DEBUG
            fprintf(stderr, "htp_connp_req_data: returning HTP_STREAM_ERROR\n");
            #endif

            // Permanent stream error.
            connp->in_status = HTP_STREAM_ERROR;

            return HTP_STREAM_ERROR;
        }
    }
}
