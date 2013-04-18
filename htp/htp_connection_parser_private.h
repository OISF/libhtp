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

#ifndef HTP_CONNECTION_PARSER_PRIVATE_H
#define	HTP_CONNECTION_PARSER_PRIVATE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "htp_core.h"

/**
 * Connection parser structure.
 */
struct htp_connp_t {

    // General fields

    /** Current parser configuration structure. */
    htp_cfg_t *cfg;

    /** The connection structure associated with this parser. */
    htp_conn_t *conn;

    /** Opaque user data associated with this parser. */
    const void *user_data;

    /**
     * On parser failure, this field will contain the error information. Do note, however,
     * that the value in this field will only be valid immediately after an error condition,
     * but it is not guaranteed to remain valid if the parser is invoked again.
     */
    htp_log_t *last_error;


    // Request parser fields

    /** Parser inbound status. Starts as HTP_OK, but may turn into HTP_ERROR. */
    enum htp_stream_state_t in_status;

    /** Parser output status. Starts as HTP_OK, but may turn into HTP_ERROR. */
    enum htp_stream_state_t out_status;

    /**
     * When true, this field indicates that there is unprocessed inbound data, and
     * that the response parsing code should stop at the end of the current request
     * in order to allow more requests to be produced.
     */
    unsigned int out_data_other_at_tx_end;

    /**
     * The time when the last request data chunk was received. Can be NULL if
     * the upstream code is not providing the timestamps when calling us.
     */
    htp_time_t in_timestamp;

    /** Pointer to the current request data chunk. */
    unsigned char *in_current_data;

    /** The length of the current request data chunk. */
    int64_t in_current_len;

    /** The offset of the next byte in the request data chunk to read. */
    int64_t in_current_read_offset;

    /**
     * The starting point of the data waiting to be consumed. This field is used
     * in the states where reading data is not the same as consumption.
     */
    int64_t in_current_consume_offset;

    /**
     * Marks the starting point of raw data within the inbound data chunk. Raw
     * data (e.g., complete headers) is sent to appropriate callbacks (e.g.,
     * REQUEST_HEADER_DATA).
     */
    int64_t in_current_receiver_offset;

    /** How many data chunks does the inbound connection stream consist of? */
    size_t in_chunk_count;

    /** The index of the first chunk used in the current request. */
    size_t in_chunk_request_index;

    /** The offset, in the entire connection stream, of the next request byte. */
    int64_t in_stream_offset;

    /**
     * The value of the request byte currently being processed. This field is
     * populated when the IN_NEXT_* or IN_PEEK_* macros are invoked.
     */
    int in_next_byte;

    /** Used to buffer a line of inbound data when buffering cannot be avoided. */
    unsigned char *in_buf;

    /** Stores the size of the buffer. Valid only when htp_tx_t::in_buf is not NULL. */
    size_t in_buf_size;

    /**
     * Stores the current value of a folded request header. Such headers span
     * multiple lines, and are processed only when all data is available.
     */
    bstr *in_header;

    /** Ongoing inbound transaction. */
    htp_tx_t *in_tx;

    /**
     * The request body length declared in a valid request header. The key here
     * is "valid". This field will not be populated if the request contains both
     * a Transfer-Encoding header and a Content-Length header.
     */
    int64_t in_content_length;

    /**
     * Holds the remaining request body length that we expect to read. This
     * field will be available only when the length of a request body is known
     * in advance, i.e. when request headers contain a Content-Length header.
     */
    int64_t in_body_data_left;

    /**
     * Holds the amount of data that needs to be read from the
     * current data chunk. Only used with chunked request bodies.
     */
    int64_t in_chunked_length;

    /** Current request parser state. */
    int (*in_state)(htp_connp_t *);

    /** Previous request parser state. Used to detect state changes. */
    int (*in_state_previous)(htp_connp_t *);

    /** The hook that should be receiving raw connection data. */
    htp_hook_t *in_data_receiver_hook;    

    // Response parser fields

    /**
     * Response counter, incremented with every new response. This field is
     * used to match responses to requests. The expectation is that for every
     * response there will already be a transaction (request) waiting.
     */
    size_t out_next_tx_index;

    /** The time when the last response data chunk was received. Can be NULL. */
    htp_time_t out_timestamp;

    /** Pointer to the current response data chunk. */
    unsigned char *out_current_data;

    /** The length of the current response data chunk. */
    int64_t out_current_len;

    /** The offset of the next byte in the response data chunk to consume. */
    int64_t out_current_read_offset;

    /**
     * The starting point of the data waiting to be consumed. This field is used
     * in the states where reading data is not the same as consumption.
     */
    int64_t out_current_consume_offset;

    /**
     * Marks the starting point of raw data within the outbound data chunk. Raw
     * data (e.g., complete headers) is sent to appropriate callbacks (e.g.,
     * RESPONSE_HEADER_DATA).
     */
    int64_t out_current_receiver_offset;

    /** The offset, in the entire connection stream, of the next response byte. */
    int64_t out_stream_offset;

    /** The value of the response byte currently being processed. */
    int out_next_byte;

    /** Used to buffer a line of outbound data when buffering cannot be avoided. */
    unsigned char *out_buf;

    /** Stores the size of the buffer. Valid only when htp_tx_t::out_buf is not NULL. */
    size_t out_buf_size;

    /**
     * Stores the current value of a folded response header. Such headers span
     * multiple lines, and are processed only when all data is available.
     */
    bstr *out_header;

    /** Ongoing outbound transaction */
    htp_tx_t *out_tx;
   
    /**
     * The length of the current response body as presented in the
     * Content-Length response header.
     */
    int64_t out_content_length;

    /** The remaining length of the current response body, if known. Set to -1 otherwise. */
    int64_t out_body_data_left;

    /**
     * Holds the amount of data that needs to be read from the
     * current response data chunk. Only used with chunked response bodies.
     */
    int64_t out_chunked_length;

    /** Current response parser state. */
    int (*out_state)(htp_connp_t *);

    /** Previous response parser state. */
    int (*out_state_previous)(htp_connp_t *);

    /** The hook that should be receiving raw connection data. */
    htp_hook_t *out_data_receiver_hook;

    /** Response decompressor used to decompress response body data. */
    htp_decompressor_t *out_decompressor;

    /** On a PUT request, this field contains additional file data. */
    htp_file_t *put_file;
};

/**
 * This function is most likely not used and/or not needed.
 * 
 * @param[in] connp
 */
void htp_connp_in_reset(htp_connp_t *connp);

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_CONNECTION_PARSER_PRIVATE_H */

