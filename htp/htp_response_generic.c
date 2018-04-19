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

/**
 * Generic response line parser.
 * 
 * @param[in] connp
 * @return HTP status
 */
htp_status_t htp_parse_response_line_generic(htp_connp_t *connp) {
    htp_tx_t *tx = connp->out_tx;
    unsigned char *data = bstr_ptr(tx->response_line);
    size_t len = bstr_len(tx->response_line);
    size_t pos = 0;

    tx->response_protocol = NULL;
    tx->response_protocol_number = HTP_PROTOCOL_INVALID;
    tx->response_status = NULL;
    tx->response_status_number = HTP_STATUS_INVALID;
    tx->response_message = NULL;

    // Ignore whitespace at the beginning of the line.
    while ((pos < len) && (htp_is_space(data[pos]))) pos++;

    size_t start = pos;

    // Find the end of the protocol string.
    while ((pos < len) && (!htp_is_space(data[pos]))) pos++;    
    if (pos - start == 0) return HTP_OK;
    
    tx->response_protocol = bstr_dup_mem(data + start, pos - start);
    if (tx->response_protocol == NULL) return HTP_ERROR;    

    tx->response_protocol_number = htp_parse_protocol(tx->response_protocol);

    #ifdef HTP_DEBUG
    fprint_raw_data(stderr, "Response protocol", bstr_ptr(tx->response_protocol), bstr_len(tx->response_protocol));
    fprintf(stderr, "Response protocol number: %d\n", tx->response_protocol_number);
    #endif

    // Ignore whitespace after the response protocol.
    while ((pos < len) && (htp_is_space(data[pos]))) pos++;
    if (pos == len) return HTP_OK;

    start = pos;

    // Find the next whitespace character.
    while ((pos < len) && (!htp_is_space(data[pos]))) pos++;    
    if (pos - start == 0) return HTP_OK;
    
    tx->response_status = bstr_dup_mem(data + start, pos - start);
    if (tx->response_status == NULL) return HTP_ERROR;

    tx->response_status_number = htp_parse_status(tx->response_status);

    #ifdef HTP_DEBUG
    fprint_raw_data(stderr, "Response status (as text)", bstr_ptr(tx->response_status), bstr_len(tx->response_status));
    fprintf(stderr, "Response status number: %d\n", tx->response_status_number);
    #endif

    // Ignore whitespace that follows the status code.
    while ((pos < len) && (isspace(data[pos]))) pos++;
    if (pos == len) return HTP_OK;

    // Assume the message stretches until the end of the line.    
    tx->response_message = bstr_dup_mem(data + pos, len - pos);
    if (tx->response_message == NULL) return HTP_ERROR;    

    #ifdef HTP_DEBUG
    fprint_raw_data(stderr, "Response status message", bstr_ptr(tx->response_message), bstr_len(tx->response_message));
    #endif

    return HTP_OK;
}

/**
 * Generic response header parser.
 * 
 * @param[in] connp
 * @param[in] h
 * @param[in] data
 * @param[in] len
 * @return HTP status
 */
htp_status_t htp_parse_response_header_generic(htp_connp_t *connp, htp_header_t *h, unsigned char *data, size_t len) {
    size_t name_start, name_end;
    size_t value_start, value_end;
    size_t prev;

    htp_chomp(data, &len);

    name_start = 0;

    // Look for the first colon.
    size_t colon_pos = 0;
    while ((colon_pos < len) && (data[colon_pos] != ':')) colon_pos++;

    if (colon_pos == len) {
        // Header line with a missing colon.

        h->flags |= HTP_FIELD_UNPARSEABLE;
        h->flags |= HTP_FIELD_INVALID;

        if (!(connp->out_tx->flags & HTP_FIELD_UNPARSEABLE)) {
            // Only once per transaction.
            connp->out_tx->flags |= HTP_FIELD_UNPARSEABLE;
            connp->out_tx->flags |= HTP_FIELD_INVALID;
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Response field invalid: missing colon.");
        }
       
        // Reset the position. We're going to treat this invalid header
        // as a header with an empty name. That will increase the probability
        // that the content will be inspected.
        colon_pos = 0;
        (void)colon_pos; // suppress scan-build warning
        name_end = 0;
        value_start = 0;
    } else {
        // Header line with a colon.
        
        if (colon_pos == 0) {
            // Empty header name.

            h->flags |= HTP_FIELD_INVALID;

            if (!(connp->out_tx->flags & HTP_FIELD_INVALID)) {
                // Only once per transaction.
                connp->out_tx->flags |= HTP_FIELD_INVALID;
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Response field invalid: empty name.");
            }
        }

        name_end = colon_pos;

        // Ignore LWS after field-name.
        prev = name_end;
        while ((prev > name_start) && (htp_is_lws(data[prev - 1]))) {
            prev--;
            name_end--;

            h->flags |= HTP_FIELD_INVALID;

            if (!(connp->out_tx->flags & HTP_FIELD_INVALID)) {
                // Only once per transaction.
                connp->out_tx->flags |= HTP_FIELD_INVALID;
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Response field invalid: LWS after name.");
            }
        }

        value_start = colon_pos + 1;
    }

    // Header value.   

    // Ignore LWS before field-content.
    while ((value_start < len) && (htp_is_lws(data[value_start]))) {
        value_start++;
    }

    // Look for the end of field-content.
    value_end = len;    
    
    // Check that the header name is a token.
    size_t i = name_start;
    while (i < name_end) {
        if (!htp_is_token(data[i])) {
            h->flags |= HTP_FIELD_INVALID;

            if (!(connp->out_tx->flags & HTP_FIELD_INVALID)) {
                connp->out_tx->flags |= HTP_FIELD_INVALID;
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Response header name is not a token.");
            }

            break;
        }

        i++;
    }

    // Now extract the name and the value.
    h->name = bstr_dup_mem(data + name_start, name_end - name_start);
    h->value = bstr_dup_mem(data + value_start, value_end - value_start);
    if ((h->name == NULL) || (h->value == NULL)) {
        bstr_free(h->name);
        bstr_free(h->value);
        return HTP_ERROR;
    }

    return HTP_OK;
}

/**
 * Generic response header line(s) processor, which assembles folded lines
 * into a single buffer before invoking the parsing function.
 * 
 * @param[in] connp
 * @param[in] data
 * @param[in] len
 * @return HTP status
 */
htp_status_t htp_process_response_header_generic(htp_connp_t *connp, unsigned char *data, size_t len) {
    // Create a new header structure.
    htp_header_t *h = calloc(1, sizeof (htp_header_t));
    if (h == NULL) return HTP_ERROR;

    if (htp_parse_response_header_generic(connp, h, data, len) != HTP_OK) {
        free(h);
        return HTP_ERROR;
    }

    #ifdef HTP_DEBUG
    fprint_bstr(stderr, "Header name", h->name);
    fprint_bstr(stderr, "Header value", h->value);
    #endif

    // Do we already have a header with the same name?
    htp_header_t *h_existing = htp_table_get(connp->out_tx->response_headers, h->name);
    if (h_existing != NULL) {
        // Keep track of repeated same-name headers.
        h_existing->flags |= HTP_FIELD_REPEATED;
                
        // Having multiple C-L headers is against the RFC but many
        // browsers ignore the subsequent headers if the values are the same.
        if (bstr_cmp_c_nocase(h->name, "Content-Length") == 0) {
            // Don't use string comparison here because we want to
            // ignore small formatting differences.

            int64_t existing_cl, new_cl;

            existing_cl = htp_parse_content_length(h_existing->value);
            new_cl = htp_parse_content_length(h->value);
            if ((existing_cl == -1) || (new_cl == -1) || (existing_cl != new_cl)) {
                // Ambiguous response C-L value.
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Ambiguous response C-L value");

                bstr_free(h->name);
                bstr_free(h->value);
                free(h);
                
                return HTP_ERROR;
            }

            // Ignoring the new C-L header that has the same value as the previous ones.
        } else {            
            // Add to the existing header.

            bstr *new_value = bstr_expand(h_existing->value, bstr_len(h_existing->value) + 2 + bstr_len(h->value));
            if (new_value == NULL) {
                bstr_free(h->name);
                bstr_free(h->value);
                free(h);
                return HTP_ERROR;
            }

            h_existing->value = new_value;
            bstr_add_mem_noex(h_existing->value, (unsigned char *) ", ", 2);
            bstr_add_noex(h_existing->value, h->value);
        }

        // The new header structure is no longer needed.
        bstr_free(h->name);
        bstr_free(h->value);
        free(h);       
    } else {
        // Add as a new header.
        if (htp_table_add(connp->out_tx->response_headers, h->name, h) != HTP_OK) {
            bstr_free(h->name);
            bstr_free(h->value);
            free(h);
            return HTP_ERROR;
        }
    }
   
    return HTP_OK;
}
