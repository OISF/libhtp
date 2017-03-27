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

#define OUT_TEST_NEXT_BYTE_OR_RETURN(X) \
if ((X)->out_current_read_offset >= (X)->out_current_len) { \
    return HTP_DATA; \
}

#define OUT_PEEK_NEXT(X) \
if ((X)->out_current_read_offset >= (X)->out_current_len) { \
    (X)->out_next_byte = -1; \
} else { \
    (X)->out_next_byte = (X)->out_current_data[(X)->out_current_read_offset]; \
}

#define OUT_NEXT_BYTE(X) \
if ((X)->out_current_read_offset < (X)->out_current_len) { \
    (X)->out_next_byte = (X)->out_current_data[(X)->out_current_read_offset]; \
    (X)->out_current_read_offset++; \
    (X)->out_current_consume_offset++; \
    (X)->out_stream_offset++; \
} else { \
    (X)->out_next_byte = -1; \
}

#define OUT_NEXT_BYTE_OR_RETURN(X) \
if ((X)->out_current_read_offset < (X)->out_current_len) { \
    (X)->out_next_byte = (X)->out_current_data[(X)->out_current_read_offset]; \
    (X)->out_current_read_offset++; \
    (X)->out_current_consume_offset++; \
    (X)->out_stream_offset++; \
} else { \
    return HTP_DATA; \
}

#define OUT_COPY_BYTE_OR_RETURN(X) \
if ((X)->out_current_read_offset < (X)->out_current_len) { \
    (X)->out_next_byte = (X)->out_current_data[(X)->out_current_read_offset]; \
    (X)->out_current_read_offset++; \
    (X)->out_stream_offset++; \
} else { \
    return HTP_DATA_BUFFER; \
}

#define REQUEST_URI_NOT_SEEN "/libhtp::request_uri_not_seen"

/**
 * Sends outstanding connection data to the currently active data receiver hook.
 *
 * @param[in] connp
 * @param[in] is_last
 * @return HTP_OK, or a value returned from a callback.
 */
static htp_status_t htp_connp_res_receiver_send_data(htp_connp_t *connp, int is_last) {
    if (connp->out_data_receiver_hook == NULL) return HTP_OK;

    htp_tx_data_t d;
    d.tx = connp->out_tx;
    d.data = connp->out_current_data + connp->out_current_receiver_offset;
    d.len = connp->out_current_read_offset - connp->out_current_receiver_offset;
    d.is_last = is_last;

    htp_status_t rc = htp_hook_run_all(connp->out_data_receiver_hook, &d);
    if (rc != HTP_OK) return rc;

    connp->out_current_receiver_offset = connp->out_current_read_offset;

    return HTP_OK;
}

/**
 * Finalizes an existing data receiver hook by sending any outstanding data to it. The
 * hook is then removed so that it receives no more data.
 *
 * @param[in] connp
 * @return HTP_OK, or a value returned from a callback.
 */
htp_status_t htp_connp_res_receiver_finalize_clear(htp_connp_t *connp) {
    if (connp->out_data_receiver_hook == NULL) return HTP_OK;

    htp_status_t rc = htp_connp_res_receiver_send_data(connp, 1 /* last */);

    connp->out_data_receiver_hook = NULL;

    return rc;
}

/**
 * Configures the data receiver hook. If there is a previous hook, it will be finalized and cleared.
 *
 * @param[in] connp
 * @param[in] data_receiver_hook
 * @return HTP_OK, or a value returned from a callback.
 */
static htp_status_t htp_connp_res_receiver_set(htp_connp_t *connp, htp_hook_t *data_receiver_hook) {
    htp_connp_res_receiver_finalize_clear(connp);

    connp->out_data_receiver_hook = data_receiver_hook;
    connp->out_current_receiver_offset = connp->out_current_read_offset;

    return HTP_OK;
}

/**
 * Handles request parser state changes. At the moment, this function is used only
 * to configure data receivers, which are sent raw connection data.
 *
 * @param[in] connp
 * @return HTP_OK, or a value returned from a callback.
 */
static htp_status_t htp_res_handle_state_change(htp_connp_t *connp) {
    if (connp->out_state_previous == connp->out_state) return HTP_OK;

    if (connp->out_state == htp_connp_RES_HEADERS) {
        htp_status_t rc = HTP_OK;

        switch (connp->out_tx->response_progress) {
            case HTP_RESPONSE_HEADERS:
                rc = htp_connp_res_receiver_set(connp, connp->out_tx->cfg->hook_response_header_data);
                break;

            case HTP_RESPONSE_TRAILER:
                rc = htp_connp_res_receiver_set(connp, connp->out_tx->cfg->hook_response_trailer_data);
                break;

            default:
                // Do nothing; receivers are currently used only for header blocks.
                break;
        }

        if (rc != HTP_OK) return rc;
    }

    // Same comment as in htp_req_handle_state_change(). Below is a copy.

    // Initially, I had the finalization of raw data sending here, but that
    // caused the last REQUEST_HEADER_DATA hook to be invoked after the
    // REQUEST_HEADERS hook -- which I thought made no sense. For that reason,
    // the finalization is now initiated from the request header processing code,
    // which is less elegant but provides a better user experience. Having some
    // (or all) hooks to be invoked on state change might work better.

    connp->out_state_previous = connp->out_state;

    return HTP_OK;
}

/**
 * If there is any data left in the outbound data chunk, this function will preserve
 * it for later consumption. The maximum amount accepted for buffering is controlled
 * by htp_config_t::field_limit_hard.
 *
 * @param[in] connp
 * @return HTP_OK, or HTP_ERROR on fatal failure.
 */
static htp_status_t htp_connp_res_buffer(htp_connp_t *connp) {
    if (connp->out_current_data == NULL) return HTP_OK;
    
    unsigned char *data = connp->out_current_data + connp->out_current_consume_offset;
    size_t len = connp->out_current_read_offset - connp->out_current_consume_offset;

    // Check the hard (buffering) limit.

    size_t newlen = connp->out_buf_size + len;   

    // When calculating the size of the buffer, take into account the
    // space we're using for the response header buffer.
    if (connp->out_header != NULL) {
        newlen += bstr_len(connp->out_header);
    }

    if (newlen > connp->out_tx->cfg->field_limit_hard) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Response the buffer limit: size %zd limit %zd.",
                newlen, connp->out_tx->cfg->field_limit_hard);
        return HTP_ERROR;
    }

    // Copy the data remaining in the buffer.

    if (connp->out_buf == NULL) {
        connp->out_buf = malloc(len);
        if (connp->out_buf == NULL) return HTP_ERROR;
        memcpy(connp->out_buf, data, len);
        connp->out_buf_size = len;
    } else {
        size_t newsize = connp->out_buf_size + len;
        unsigned char *newbuf = realloc(connp->out_buf, newsize);
        if (newbuf == NULL) return HTP_ERROR;
        connp->out_buf = newbuf;
        memcpy(connp->out_buf + connp->out_buf_size, data, len);
        connp->out_buf_size = newsize;
    }

    // Reset the consumer position.
    connp->out_current_consume_offset = connp->out_current_read_offset;

    return HTP_OK;
}

/**
 * Returns to the caller the memory region that should be processed next. This function
 * hides away the buffering process from the rest of the code, allowing it to work with
 * non-buffered data that's in the outbound chunk, or buffered data that's in our structures.
 *
 * @param[in] connp
 * @param[out] data
 * @param[out] len
 * @return HTP_OK
 */
static htp_status_t htp_connp_res_consolidate_data(htp_connp_t *connp, unsigned char **data, size_t *len) {    
    if (connp->out_buf == NULL) {
        // We do not have any data buffered; point to the current data chunk.
        *data = connp->out_current_data + connp->out_current_consume_offset;
        *len = connp->out_current_read_offset - connp->out_current_consume_offset;
    } else {
        // We do have data in the buffer. Add data from the current
        // chunk, and point to the consolidated buffer.
        if (htp_connp_res_buffer(connp) != HTP_OK) {
            return HTP_ERROR;
        }

        *data = connp->out_buf;
        *len = connp->out_buf_size;
    }

    return HTP_OK;
}

/**
 * Clears buffered outbound data and resets the consumer position to the reader position.
 *
 * @param[in] connp
 */
static void htp_connp_res_clear_buffer(htp_connp_t *connp) {
    connp->out_current_consume_offset = connp->out_current_read_offset;

    if (connp->out_buf != NULL) {
        free(connp->out_buf);
        connp->out_buf = NULL;
        connp->out_buf_size = 0;
    }
}

/**
 * Consumes bytes until the end of the current line.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_RES_BODY_CHUNKED_DATA_END(htp_connp_t *connp) {
    // TODO We shouldn't really see anything apart from CR and LF,
    //      so we should warn about anything else.

    for (;;) {
        OUT_NEXT_BYTE_OR_RETURN(connp);

        connp->out_tx->response_message_len++;

        if (connp->out_next_byte == LF) {
            connp->out_state = htp_connp_RES_BODY_CHUNKED_LENGTH;

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
htp_status_t htp_connp_RES_BODY_CHUNKED_DATA(htp_connp_t *connp) {
    size_t bytes_to_consume;

    // Determine how many bytes we can consume.
    if (connp->out_current_len - connp->out_current_read_offset >= connp->out_chunked_length) {
        bytes_to_consume = connp->out_chunked_length;
    } else {
        bytes_to_consume = connp->out_current_len - connp->out_current_read_offset;
    }

    if (bytes_to_consume == 0) return HTP_DATA;

    // Consume the data.
    htp_status_t rc = htp_tx_res_process_body_data_ex(connp->out_tx, connp->out_current_data + connp->out_current_read_offset, bytes_to_consume);
    if (rc != HTP_OK) return rc;

    // Adjust the counters.
    connp->out_current_read_offset += bytes_to_consume;
    connp->out_current_consume_offset += bytes_to_consume;
    connp->out_stream_offset += bytes_to_consume;
    connp->out_chunked_length -= bytes_to_consume;

    // Have we seen the entire chunk?
    if (connp->out_chunked_length == 0) {
        connp->out_state = htp_connp_RES_BODY_CHUNKED_DATA_END;
        return HTP_OK;
    }

    return HTP_DATA;
}

/**
 * Peeks ahead into the data to try to see if it starts with a valid Chunked
 * length field.
 *
 * @returns 1 if it looks valid, 0 if it looks invalid
 */
static inline int data_probe_chunk_length(htp_connp_t *connp) {
    if (connp->out_current_read_offset - connp->out_current_consume_offset < 8) {
        // not enough data so far, consider valid still
        return 1;
    }

    unsigned char *data = connp->out_current_data + connp->out_current_consume_offset;
    size_t len = connp->out_current_read_offset - connp->out_current_consume_offset;

    size_t i = 0;
    while (i < len) {
        unsigned char c = data[i];

        if (c == 0x0d || c == 0x0a || c == 0x20 || c == 0x09 || c == 0x0b || c == 0x0c) {
            // ctl char, still good.
        } else if (isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            // real chunklen char
            return 1;
        } else {
            // leading junk, bad
            return 0;
        }
        i++;
    }
    return 1;
}

/**
 * Extracts chunk length.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_RES_BODY_CHUNKED_LENGTH(htp_connp_t *connp) {
    for (;;) {
        OUT_COPY_BYTE_OR_RETURN(connp);

        // Have we reached the end of the line? Or is this not chunked after all?
        if (connp->out_next_byte == LF || !data_probe_chunk_length(connp)) {
            unsigned char *data;
            size_t len;

            if (htp_connp_res_consolidate_data(connp, &data, &len) != HTP_OK) {
                return HTP_ERROR;
            }

            connp->out_tx->response_message_len += len;

            #ifdef HTP_DEBUG
            fprint_raw_data(stderr, "Chunk length line", data, len);
            #endif

            connp->out_chunked_length = htp_parse_chunked_length(data, len);

            // empty chunk length line, lets try to continue
            if (connp->out_chunked_length == -1004)
                continue;
            if (connp->out_chunked_length < 0) {
                // reset out_current_read_offset so htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE
                // doesn't miss the first bytes

                if (len > (size_t)connp->out_current_read_offset) {
                    connp->out_current_read_offset = 0;
                } else {
                    connp->out_current_read_offset -= len;
                }

                connp->out_state = htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE;
                connp->out_tx->response_transfer_coding = HTP_CODING_IDENTITY;

                htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                        "Response chunk encoding: Invalid chunk length: %d",
                        connp->out_chunked_length);
                return HTP_OK;
            }
            htp_connp_res_clear_buffer(connp);

            // Handle chunk length
            if (connp->out_chunked_length > 0) {
                // More data available
                connp->out_state = htp_connp_RES_BODY_CHUNKED_DATA;
            } else if (connp->out_chunked_length == 0) {
                // End of data
                connp->out_state = htp_connp_RES_HEADERS;
                connp->out_tx->response_progress = HTP_RESPONSE_TRAILER;
            }

            return HTP_OK;
        }
    }

    return HTP_ERROR;
}

/**
 * Processes an identity response body of known length.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_RES_BODY_IDENTITY_CL_KNOWN(htp_connp_t *connp) {
    size_t bytes_to_consume;   
        
    // Determine how many bytes we can consume.
    if (connp->out_current_len - connp->out_current_read_offset >= connp->out_body_data_left) {
        bytes_to_consume = connp->out_body_data_left;
    } else {
        bytes_to_consume = connp->out_current_len - connp->out_current_read_offset;
    }       
    
    if (bytes_to_consume == 0) return HTP_DATA;    

    // Consume the data.
    htp_status_t rc = htp_tx_res_process_body_data_ex(connp->out_tx, connp->out_current_data + connp->out_current_read_offset, bytes_to_consume);
    if (rc != HTP_OK) return rc;

    // Adjust the counters.
    connp->out_current_read_offset += bytes_to_consume;
    connp->out_current_consume_offset += bytes_to_consume;
    connp->out_stream_offset += bytes_to_consume;
    connp->out_body_data_left -= bytes_to_consume;

    // Have we seen the entire response body?    
    if (connp->out_body_data_left == 0) {
        connp->out_state = htp_connp_RES_FINALIZE;
        return HTP_OK;
    }

    return HTP_DATA;
}

/**
 * Processes identity response body of unknown length. In this case, we assume the
 * response body consumes all data until the end of the stream.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE(htp_connp_t *connp) {        
    // Consume all data from the input buffer.
    size_t bytes_to_consume = connp->out_current_len - connp->out_current_read_offset;

    #ifdef HTP_DEBUG
    fprintf(stderr, "bytes_to_consume %"PRIuMAX, (uintmax_t)bytes_to_consume);
    #endif
    if (bytes_to_consume != 0) {
        htp_status_t rc = htp_tx_res_process_body_data_ex(connp->out_tx, connp->out_current_data + connp->out_current_read_offset, bytes_to_consume);
        if (rc != HTP_OK) return rc;

        // Adjust the counters.
        connp->out_current_read_offset += bytes_to_consume;
        connp->out_current_consume_offset += bytes_to_consume;
        connp->out_stream_offset += bytes_to_consume;        
    }

    // Have we seen the entire response body?
    if (connp->out_status == HTP_STREAM_CLOSED) {
        connp->out_state = htp_connp_RES_FINALIZE;
        return HTP_OK;
    }
   
    return HTP_DATA;
}

/**
 * Determines presence (and encoding) of a response body.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_RES_BODY_DETERMINE(htp_connp_t *connp) {
    // If the request uses the CONNECT method, then not only are we
    // to assume there's no body, but we need to ignore all
    // subsequent data in the stream.
    if (connp->out_tx->request_method_number == HTP_M_CONNECT) {
        if ((connp->out_tx->response_status_number >= 200)
                && (connp->out_tx->response_status_number <= 299)) {
            // This is a successful CONNECT stream, which means
            // we need to switch into tunneling mode: on the
            // request side we'll now probe the tunnel data to see
            // if we need to parse or ignore it. So on the response
            // side we wrap up the tx and wait.
            connp->out_state = htp_connp_RES_FINALIZE;

            // we may have response headers
            htp_status_t rc = htp_tx_state_response_headers(connp->out_tx);
            return rc;
        } else if (connp->out_tx->response_status_number == 407) {
            // proxy telling us to auth
            connp->in_status = HTP_STREAM_DATA;
        } else {
            // This is a failed CONNECT stream, which means that
            // we can unblock request parsing
            connp->in_status = HTP_STREAM_DATA;

            // We are going to continue processing this transaction,
            // adding a note for ourselves to stop at the end (because
            // we don't want to see the beginning of a new transaction).
            connp->out_data_other_at_tx_end = 1;
        }
    }

    // Check for "101 Switching Protocol" response.
    // If it's seen, it means that traffic after empty line following headers
    // is no longer HTTP. We can treat it similarly to CONNECT.
    // Unlike CONNECT, however, upgrades from HTTP to HTTP seem
    // rather unlikely, so don't try to probe tunnel for nested HTTP,
    // and switch to tunnel mode right away.
    if (connp->out_tx->response_status_number == 101) {
        connp->out_state = htp_connp_RES_FINALIZE;

        connp->in_status = HTP_STREAM_TUNNEL;
        connp->out_status = HTP_STREAM_TUNNEL;

        // we may have response headers
        htp_status_t rc = htp_tx_state_response_headers(connp->out_tx);
        return rc;
    }

    // Check for an interim "100 Continue" response. Ignore it if found, and revert back to RES_LINE.
    if (connp->out_tx->response_status_number == 100) {
        if (connp->out_tx->seen_100continue != 0) {
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Already seen 100-Continue.");
            return HTP_ERROR;
        }

        // Ignore any response headers seen so far.
        htp_header_t *h = NULL;
        for (size_t i = 0, n = htp_table_size(connp->out_tx->response_headers); i < n; i++) {
            h = htp_table_get_index(connp->out_tx->response_headers, i, NULL);
            bstr_free(h->name);
            bstr_free(h->value);
            free(h);
        }

        htp_table_clear(connp->out_tx->response_headers);

        // Expecting to see another response line next.
        connp->out_state = htp_connp_RES_LINE;
        connp->out_tx->response_progress = HTP_RESPONSE_LINE;
        connp->out_tx->seen_100continue++;

        return HTP_OK;
    }

    // 1. Any response message which MUST NOT include a message-body
    //  (such as the 1xx, 204, and 304 responses and any response to a HEAD
    //  request) is always terminated by the first empty line after the
    //  header fields, regardless of the entity-header fields present in the
    //  message.
    if (((connp->out_tx->response_status_number >= 100) && (connp->out_tx->response_status_number <= 199))
            || (connp->out_tx->response_status_number == 204) || (connp->out_tx->response_status_number == 304)
            || (connp->out_tx->request_method_number == HTP_M_HEAD)) {
        // There's no response body
        connp->out_tx->response_transfer_coding = HTP_CODING_NO_BODY;
        connp->out_state = htp_connp_RES_FINALIZE;
    } else {
        // We have a response body

        htp_header_t *ct = htp_table_get_c(connp->out_tx->response_headers, "content-type");
        htp_header_t *cl = htp_table_get_c(connp->out_tx->response_headers, "content-length");
        htp_header_t *te = htp_table_get_c(connp->out_tx->response_headers, "transfer-encoding");

        if (ct != NULL) {
            connp->out_tx->response_content_type = bstr_dup_lower(ct->value);
            if (connp->out_tx->response_content_type == NULL) return HTP_ERROR;

            // Ignore parameters
            unsigned char *data = bstr_ptr(connp->out_tx->response_content_type);
            size_t len = bstr_len(ct->value);
            size_t newlen = 0;
            while (newlen < len) {
                // TODO Some platforms may do things differently here.
                if (htp_is_space(data[newlen]) || (data[newlen] == ';')) {
                    bstr_adjust_len(connp->out_tx->response_content_type, newlen);
                    break;
                }

                newlen++;
            }
        }

        // 2. If a Transfer-Encoding header field (section 14.40) is present and
        //   indicates that the "chunked" transfer coding has been applied, then
        //   the length is defined by the chunked encoding (section 3.6).
        if ((te != NULL) && (bstr_index_of_c_nocase(te->value, "chunked") != -1)) {
            if (bstr_cmp_c_nocase(te->value, "chunked") != 0) {
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                        "Transfer-encoding has abnormal chunked value");
            }

            // spec says chunked is HTTP/1.1 only, but some browsers accept it
            // with 1.0 as well
            if (connp->out_tx->response_protocol_number < HTP_PROTOCOL_1_1) {
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0,
                        "Chunked transfer-encoding on HTTP/0.9 or HTTP/1.0");
            }

            // If the T-E header is present we are going to use it.
            connp->out_tx->response_transfer_coding = HTP_CODING_CHUNKED;

            // We are still going to check for the presence of C-L
            if (cl != NULL) {
                // This is a violation of the RFC
                connp->out_tx->flags |= HTP_REQUEST_SMUGGLING;
            }

            connp->out_state = htp_connp_RES_BODY_CHUNKED_LENGTH;
            connp->out_tx->response_progress = HTP_RESPONSE_BODY;
        }// 3. If a Content-Length header field (section 14.14) is present, its
            //   value in bytes represents the length of the message-body.
        else if (cl != NULL) {
            // We know the exact length
            connp->out_tx->response_transfer_coding = HTP_CODING_IDENTITY;

            // Check for multiple C-L headers
            if (cl->flags & HTP_FIELD_REPEATED) {
                connp->out_tx->flags |= HTP_REQUEST_SMUGGLING;
            }

            // Get body length
            connp->out_tx->response_content_length = htp_parse_content_length(cl->value);
            if (connp->out_tx->response_content_length < 0) {
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Invalid C-L field in response: %d",
                        connp->out_tx->response_content_length);
                return HTP_ERROR;
            } else {
                connp->out_content_length = connp->out_tx->response_content_length;
                connp->out_body_data_left = connp->out_content_length;

                if (connp->out_content_length != 0) {
                    connp->out_state = htp_connp_RES_BODY_IDENTITY_CL_KNOWN;
                    connp->out_tx->response_progress = HTP_RESPONSE_BODY;
                } else {                    
                    connp->out_state = htp_connp_RES_FINALIZE;
                }
            }
        } else {
            // 4. If the message uses the media type "multipart/byteranges", which is
            //   self-delimiting, then that defines the length. This media type MUST
            //   NOT be used unless the sender knows that the recipient can parse it;
            //   the presence in a request of a Range header with multiple byte-range
            //   specifiers implies that the client can parse multipart/byteranges
            //   responses.
            if (ct != NULL) {
                // TODO Handle multipart/byteranges
                if (bstr_index_of_c_nocase(ct->value, "multipart/byteranges") != -1) {
                    htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                            "C-T multipart/byteranges in responses not supported");
                    return HTP_ERROR;
                }
            }

            // 5. By the server closing the connection. (Closing the connection
            //   cannot be used to indicate the end of a request body, since that
            //   would leave no possibility for the server to send back a response.)
            connp->out_state = htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE;
            connp->out_tx->response_transfer_coding = HTP_CODING_IDENTITY;
            connp->out_tx->response_progress = HTP_RESPONSE_BODY;
            connp->out_body_data_left = -1;
        }
    }

    // NOTE We do not need to check for short-style HTTP/0.9 requests here because
    //      that is done earlier, before response line parsing begins

    htp_status_t rc = htp_tx_state_response_headers(connp->out_tx);
    if (rc != HTP_OK) return rc;

    return HTP_OK;
}

/**
 * Parses response headers.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_RES_HEADERS(htp_connp_t *connp) {
    for (;;) {
        OUT_COPY_BYTE_OR_RETURN(connp);

        // Have we reached the end of the line?
        if (connp->out_next_byte == LF || connp->out_next_byte == CR) {

            if (connp->out_next_byte == CR) {
                OUT_PEEK_NEXT(connp);
                if (connp->out_next_byte == -1) {
                    return HTP_DATA_BUFFER;
                } else if (connp->out_next_byte == LF) {
                    OUT_COPY_BYTE_OR_RETURN(connp);
                }
            }

            unsigned char *data;
            size_t len;

            if (htp_connp_res_consolidate_data(connp, &data, &len) != HTP_OK) {
                return HTP_ERROR;
            }

            #ifdef HTP_DEBUG
            fprint_raw_data(stderr, __func__, data, len);
            #endif

            // Should we terminate headers?
            if (htp_connp_is_line_terminator(connp, data, len)) {
                // Parse previous header, if any.
                if (connp->out_header != NULL) {
                    if (connp->cfg->process_response_header(connp, bstr_ptr(connp->out_header),
                            bstr_len(connp->out_header)) != HTP_OK) return HTP_ERROR;

                    bstr_free(connp->out_header);
                    connp->out_header = NULL;
                }

                htp_connp_res_clear_buffer(connp);

                // We've seen all response headers.
                if (connp->out_tx->response_progress == HTP_RESPONSE_HEADERS) {
                    // Response headers.

                    // The next step is to determine if this response has a body.
                    connp->out_state = htp_connp_RES_BODY_DETERMINE;
                } else {
                    // Response trailer.

                    // Finalize sending raw trailer data.
                    htp_status_t rc = htp_connp_res_receiver_finalize_clear(connp);
                    if (rc != HTP_OK) return rc;

                    // Run hook response_TRAILER.
                    rc = htp_hook_run_all(connp->cfg->hook_response_trailer, connp->out_tx);
                    if (rc != HTP_OK) return rc;

                    // The next step is to finalize this response.
                    connp->out_state = htp_connp_RES_FINALIZE;
                }

                return HTP_OK;
            }

            htp_chomp(data, &len);

            // Check for header folding.
            if (htp_connp_is_line_folded(data, len) == 0) {
                // New header line.

                // Parse previous header, if any.
                if (connp->out_header != NULL) {
                    if (connp->cfg->process_response_header(connp, bstr_ptr(connp->out_header),
                            bstr_len(connp->out_header)) != HTP_OK) return HTP_ERROR;

                    bstr_free(connp->out_header);
                    connp->out_header = NULL;
                }

                OUT_PEEK_NEXT(connp);

                if (htp_is_folding_char(connp->out_next_byte) == 0) {
                    // Because we know this header is not folded, we can process the buffer straight away.
                    if (connp->cfg->process_response_header(connp, data, len) != HTP_OK) return HTP_ERROR;
                } else {
                    // Keep the partial header data for parsing later.
                    connp->out_header = bstr_dup_mem(data, len);
                    if (connp->out_header == NULL) return HTP_ERROR;
                }
            } else {
                // Folding; check that there's a previous header line to add to.
                if (connp->out_header == NULL) {
                    // Invalid folding.

                    // Warn only once per transaction.
                    if (!(connp->out_tx->flags & HTP_INVALID_FOLDING)) {
                        connp->out_tx->flags |= HTP_INVALID_FOLDING;
                        htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Invalid response field folding");
                    }

                    // Keep the header data for parsing later.
                    connp->out_header = bstr_dup_mem(data, len);
                    if (connp->out_header == NULL) return HTP_ERROR;
                } else {
                    // Add to the existing header.                    
                    bstr *new_out_header = bstr_add_mem(connp->out_header, data, len);
                    if (new_out_header == NULL) return HTP_ERROR;
                    connp->out_header = new_out_header;
                }
            }

            htp_connp_res_clear_buffer(connp);
        }
    }

    return HTP_ERROR;
}

/**
 * Parses response line.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_RES_LINE(htp_connp_t *connp) {
    for (;;) {
        // Don't try to get more data if the stream is closed. If we do, we'll return, asking for more data.
        if (connp->out_status != HTP_STREAM_CLOSED) {
            // Get one byte
            OUT_COPY_BYTE_OR_RETURN(connp);
        }

        // Have we reached the end of the line? We treat stream closure as end of line in
        // order to handle the case when the first line of the response is actually response body
        // (and we wish it processed as such).
        if ((connp->out_next_byte == LF)||(connp->out_status == HTP_STREAM_CLOSED)) {
            unsigned char *data;
            size_t len;

            if (htp_connp_res_consolidate_data(connp, &data, &len) != HTP_OK) {
                return HTP_ERROR;
            }

            #ifdef HTP_DEBUG
            fprint_raw_data(stderr, __func__, data, len);
            #endif

            // Is this a line that should be ignored?
            if (htp_connp_is_line_ignorable(connp, data, len)) {
                // We have an empty/whitespace line, which we'll note, ignore and move on
                connp->out_tx->response_ignored_lines++;

                // TODO How many lines are we willing to accept?

                // Start again
                htp_connp_res_clear_buffer(connp);

                return HTP_OK;
            }

            // Deallocate previous response line allocations, which we would have on a 100 response.

            if (connp->out_tx->response_line != NULL) {
                bstr_free(connp->out_tx->response_line);
                connp->out_tx->response_line = NULL;
            }

            if (connp->out_tx->response_protocol != NULL) {
                bstr_free(connp->out_tx->response_protocol);
                connp->out_tx->response_protocol = NULL;
            }

            if (connp->out_tx->response_status != NULL) {
                bstr_free(connp->out_tx->response_status);
                connp->out_tx->response_status = NULL;
            }

            if (connp->out_tx->response_message != NULL) {
                bstr_free(connp->out_tx->response_message);
                connp->out_tx->response_message = NULL;
            }

            // Process response line.           

            int chomp_result = htp_chomp(data, &len);

            // If the response line is invalid, determine if it _looks_ like
            // a response line. If it does not look like a line, process the
            // data as a response body because that is what browsers do.
           
            if (htp_treat_response_line_as_body(data, len)) {
                connp->out_tx->response_content_encoding_processing = HTP_COMPRESSION_NONE;

                htp_status_t rc = htp_tx_res_process_body_data_ex(connp->out_tx, data, len + chomp_result);
                if (rc != HTP_OK) return rc;

                // Continue to process response body. Because we don't have
                // any headers to parse, we assume the body continues until
                // the end of the stream.
                connp->out_tx->response_transfer_coding = HTP_CODING_IDENTITY;
                connp->out_tx->response_progress = HTP_RESPONSE_BODY;
                connp->out_state = htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE;               
                connp->out_body_data_left = -1;

                // Clean response line allocations when processed as body
                bstr_free(connp->out_tx->response_line);
                connp->out_tx->response_line = NULL;

                bstr_free(connp->out_tx->response_protocol);
                connp->out_tx->response_protocol = NULL;

                bstr_free(connp->out_tx->response_status);
                connp->out_tx->response_status = NULL;

                bstr_free(connp->out_tx->response_message);
                connp->out_tx->response_message = NULL;

                return HTP_OK;
            }

            connp->out_tx->response_line = bstr_dup_mem(data, len);
            if (connp->out_tx->response_line == NULL) return HTP_ERROR;

            if (connp->cfg->parse_response_line(connp) != HTP_OK) return HTP_ERROR;

            htp_status_t rc = htp_tx_state_response_line(connp->out_tx);
            if (rc != HTP_OK) return rc;

            htp_connp_res_clear_buffer(connp);

            // Move on to the next phase.
            connp->out_state = htp_connp_RES_HEADERS;
            connp->out_tx->response_progress = HTP_RESPONSE_HEADERS;

            return HTP_OK;
        }
    }

    return HTP_ERROR;
}

size_t htp_connp_res_data_consumed(htp_connp_t *connp) {
    return connp->out_current_read_offset;
}

htp_status_t htp_connp_RES_FINALIZE(htp_connp_t *connp) {
    return htp_tx_state_response_complete_ex(connp->out_tx, 0 /* not hybrid mode */);
}

/**
 * The response idle state will initialize response processing, as well as
 * finalize each transactions after we are done with it.
 *
 * @param[in] connp
 * @returns HTP_OK on state change, HTP_ERROR on error, or HTP_DATA when more data is needed.
 */
htp_status_t htp_connp_RES_IDLE(htp_connp_t *connp) {

    // We want to start parsing the next response (and change
    // the state from IDLE) only if there's at least one
    // byte of data available. Otherwise we could be creating
    // new structures even if there's no more data on the
    // connection.
    OUT_TEST_NEXT_BYTE_OR_RETURN(connp);

    // Parsing a new response

    // Find the next outgoing transaction
    // If there is none, we just create one so that responses without
    // request can still be processed.
    connp->out_tx = htp_list_get(connp->conn->transactions, connp->out_next_tx_index);
    if (connp->out_tx == NULL) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Unable to match response to request");
        connp->out_tx = htp_connp_tx_create(connp);
        if (connp->out_tx == NULL) {
            return HTP_ERROR;
        }
        connp->out_tx->parsed_uri = htp_uri_alloc();
        if (connp->out_tx->parsed_uri == NULL) {
            return HTP_ERROR;
        }
        connp->out_tx->parsed_uri->path = bstr_dup_c(REQUEST_URI_NOT_SEEN);
        if (connp->out_tx->parsed_uri->path == NULL) {
            return HTP_ERROR;
        }
        connp->out_tx->request_uri = bstr_dup_c(REQUEST_URI_NOT_SEEN);
        if (connp->out_tx->request_uri == NULL) {
            return HTP_ERROR;
        }

        connp->in_state = htp_connp_REQ_FINALIZE;
#ifdef HTP_DEBUG
        fprintf(stderr, "picked up response w/o request");
#endif
        // We've used one transaction
        connp->out_next_tx_index++;
    } else {
        // We've used one transaction
        connp->out_next_tx_index++;

        // TODO Detect state mismatch

        connp->out_content_length = -1;
        connp->out_body_data_left = -1;
    }

    htp_status_t rc = htp_tx_state_response_start(connp->out_tx);
    if (rc != HTP_OK) return rc;

    return HTP_OK;
}

int htp_connp_res_data(htp_connp_t *connp, const htp_time_t *timestamp, const void *data, size_t len) {
    #ifdef HTP_DEBUG
    fprintf(stderr, "htp_connp_res_data(connp->out_status %x)\n", connp->out_status);
    fprint_raw_data(stderr, __func__, data, len);
    #endif

    // Return if the connection is in stop state
    if (connp->out_status == HTP_STREAM_STOP) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_INFO, 0, "Outbound parser is in HTP_STREAM_STOP");

        return HTP_STREAM_STOP;
    }

    // Return if the connection has had a fatal error
    if (connp->out_status == HTP_STREAM_ERROR) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Outbound parser is in HTP_STREAM_ERROR");

        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_DATA (previous error)\n");
        #endif

        return HTP_STREAM_ERROR;
    }

    // Sanity check: we must have a transaction pointer if the state is not IDLE (no outbound transaction)
    if ((connp->out_tx == NULL)&&(connp->out_state != htp_connp_RES_IDLE)) {
        connp->out_status = HTP_STREAM_ERROR;

        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Missing outbound transaction data");

        return HTP_STREAM_ERROR;
    }

    // If the length of the supplied data chunk is zero, proceed
    // only if the stream has been closed. We do not allow zero-sized
    // chunks in the API, but we use it internally to force the parsers
    // to finalize parsing.
    if (((data == NULL) || (len == 0)) && (connp->out_status != HTP_STREAM_CLOSED)) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Zero-length data chunks are not allowed");

        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_DATA (zero-length chunk)\n");
        #endif

        return HTP_STREAM_CLOSED;
    }

    // Remember the timestamp of the current response data chunk
    if (timestamp != NULL) {
        memcpy(&connp->out_timestamp, timestamp, sizeof (*timestamp));
    }

    // Store the current chunk information
    connp->out_current_data = (unsigned char *) data;
    connp->out_current_len = len;
    connp->out_current_read_offset = 0;
    connp->out_current_consume_offset = 0;
    connp->out_current_receiver_offset = 0;

    htp_conn_track_outbound_data(connp->conn, len, timestamp);

    // Return without processing any data if the stream is in tunneling
    // mode (which it would be after an initial CONNECT transaction.
    if (connp->out_status == HTP_STREAM_TUNNEL) {
        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_TUNNEL\n");
        #endif

        return HTP_STREAM_TUNNEL;
    }

    // Invoke a processor, in a loop, until an error
    // occurs or until we run out of data. Many processors
    // will process a request, each pointing to the next
    // processor that needs to run.
    for (;;) {
        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_connp_res_data: out state=%s, progress=%s\n",
                htp_connp_out_state_as_string(connp),
                htp_tx_response_progress_as_string(connp->out_tx));
        #endif

        // Return if there's been an error
        // or if we've run out of data. We are relying
        // on processors to add error messages, so we'll
        // keep quiet here.
        htp_status_t rc = connp->out_state(connp);
        if (rc == HTP_OK) {
            if (connp->out_status == HTP_STREAM_TUNNEL) {
                #ifdef HTP_DEBUG
                fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_TUNNEL\n");
                #endif

                return HTP_STREAM_TUNNEL;
            }

            rc = htp_res_handle_state_change(connp);
        }

        if (rc != HTP_OK) {
            // Do we need more data?
            if ((rc == HTP_DATA) || (rc == HTP_DATA_BUFFER)) {
                htp_connp_res_receiver_send_data(connp, 0 /* not last */);

                if (rc == HTP_DATA_BUFFER) {
                    if (htp_connp_res_buffer(connp) != HTP_OK) {
                        connp->out_status = HTP_STREAM_ERROR;
                        return HTP_STREAM_ERROR;
                    }
                }

                #ifdef HTP_DEBUG
                fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_DATA\n");
                #endif

                connp->out_status = HTP_STREAM_DATA;

                return HTP_STREAM_DATA;
            }

            // Check for stop
            if (rc == HTP_STOP) {
                #ifdef HTP_DEBUG
                fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_STOP\n");
                #endif

                connp->out_status = HTP_STREAM_STOP;

                return HTP_STREAM_STOP;
            }

            // Check for suspended parsing
            if (rc == HTP_DATA_OTHER) {
                // We might have actually consumed the entire data chunk?
                if (connp->out_current_read_offset >= connp->out_current_len) {
                    #ifdef HTP_DEBUG
                    fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_DATA (suspended parsing)\n");
                    #endif

                    connp->out_status = HTP_STREAM_DATA;

                    // Do not send STREAM_DATE_DATA_OTHER if we've
                    // consumed the entire chunk
                    return HTP_STREAM_DATA;
                } else {
                    #ifdef HTP_DEBUG
                    fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_DATA_OTHER\n");
                    #endif

                    connp->out_status = HTP_STREAM_DATA_OTHER;

                    // Partial chunk consumption
                    return HTP_STREAM_DATA_OTHER;
                }
            }

            #ifdef HTP_DEBUG
            fprintf(stderr, "htp_connp_res_data: returning HTP_STREAM_ERROR\n");
            #endif

            // Permanent stream error.
            connp->out_status = HTP_STREAM_ERROR;

            return HTP_STREAM_ERROR;
        }
    }
}
