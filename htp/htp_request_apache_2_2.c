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
 * Extract one request header. A header can span multiple lines, in
 * which case they will be folded into one before parsing is attempted.
 *
 * @param connp
 * @return HTP_OK or HTP_ERROR
 */
int htp_process_request_header_apache_2_2(htp_connp_t *connp) {
    bstr *tempstr = NULL;
    unsigned char *data = NULL;
    size_t len = 0;

    // Create new header structure
    htp_header_t *h = calloc(1, sizeof (htp_header_t));
    if (h == NULL) return HTP_ERROR;

    // Ensure we have the necessary header data in a single buffer
    if (connp->in_header_line_index + 1 == connp->in_header_line_counter) {
        // Single line
        htp_header_line_t *hl = list_get(connp->in_tx->request_header_lines,
            connp->in_header_line_index);
        if (hl == NULL) {
            // Internal error
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                "Process request header (Apache 2.2): Internal error");
            free(h);
            return HTP_ERROR;
        }

        data = (unsigned char *) bstr_ptr(hl->line);
        len = bstr_len(hl->line);
        hl->header = h;
    } else {
        // Multiple lines (folded)
        int i = 0;

        for (i = connp->in_header_line_index; i < connp->in_header_line_counter; i++) {
            htp_header_line_t *hl = list_get(connp->in_tx->request_header_lines, i);            
            len += bstr_len(hl->line);
        }

        tempstr = bstr_alloc(len);
        if (tempstr == NULL) {
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                "Process request header (Apache 2.2): Failed to allocate bstring of %d bytes", len);
            free(h);
            return HTP_ERROR;
        }

        for (i = connp->in_header_line_index; i < connp->in_header_line_counter; i++) {
            htp_header_line_t *hl = list_get(connp->in_tx->request_header_lines, i);
            char *line = bstr_ptr(hl->line);
            size_t llen = bstr_len(hl->line);
            htp_chomp((unsigned char *)line, &llen);            
            bstr_add_mem_noex(tempstr, line, llen);
            hl->header = h;

            if (i != connp->in_header_line_index) {
                hl->flags |= HTP_FIELD_FOLDED;
            }
        }

        h->flags |= HTP_FIELD_FOLDED;

        data = (unsigned char *) bstr_ptr(tempstr);
        len = bstr_len(tempstr);
    }

    // Now try to parse the header
    if (htp_parse_request_header_apache_2_2(connp, h, data, len) != HTP_OK) {
        // Note: downstream responsible for error logging
        bstr_free(&tempstr);
        free(h);
        return HTP_ERROR;
    }

    // Do we already have a header with the same name?
    htp_header_t *h_existing = table_get(connp->in_tx->request_headers, h->name);
    if (h_existing != NULL) {
        // repeated header
        int i = 0;

        // TODO Do we want to have a list of the headers that are
        //      allowed to be combined in this way?

        // Add to existing header
        bstr *new_value = bstr_expand(h_existing->value, bstr_len(h_existing->value)
            + 2 + bstr_len(h->value));
        if (new_value == NULL) {
            bstr_free(&h->name);
            bstr_free(&h->value);
            free(h);
            bstr_free(&tempstr);
            return HTP_ERROR;
        }

        h_existing->value = new_value;
        bstr_add_mem_noex(h_existing->value, ", ", 2);
        bstr_add_noex(h_existing->value, h->value);

        // replace the header references in all lines
        for (i = connp->in_header_line_index; i < connp->in_header_line_counter; i++) {
          htp_header_line_t *hl = list_get(connp->in_tx->request_header_lines, i);
          hl->header = h_existing;
        }

        // The header is no longer needed
        bstr_free(&h->name);
        bstr_free(&h->value);
        free(h);

        // Keep track of same-name headers        
        h_existing->flags |= HTP_FIELD_REPEATED;
    } else {
        // Add as a new header
        table_add(connp->in_tx->request_headers, h->name, h);
    }

    bstr_free(&tempstr);

    return HTP_OK;
}

/**
 * Parses a message header line as Apache 2.2 does.
 *
 * @param connp
 * @param h
 * @param data
 * @param len
 * @return HTP_OK or HTP_ERROR
 */
int htp_parse_request_header_apache_2_2(htp_connp_t *connp, htp_header_t *h, unsigned char *data, size_t len) {
    size_t name_start, name_end;
    size_t value_start, value_end;

    htp_chomp(data, &len);

    name_start = 0;

    // Look for the colon
    size_t colon_pos = 0;
    while ((colon_pos < len) && (data[colon_pos] != '\0') && (data[colon_pos] != ':')) colon_pos++;

    if ((colon_pos == len) || (data[colon_pos] == '\0')) {
        // Missing colon
        h->flags |= HTP_FIELD_UNPARSEABLE;

        if (!(connp->in_tx->flags & HTP_FIELD_UNPARSEABLE)) {
            connp->in_tx->flags |= HTP_FIELD_UNPARSEABLE;
            // Only log once per transaction
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Request field invalid: colon missing");
        }

        return HTP_ERROR;
    }

    if (colon_pos == 0) {
        // Empty header name
        h->flags |= HTP_FIELD_INVALID;

        if (!(connp->in_tx->flags & HTP_FIELD_INVALID)) {
            connp->in_tx->flags |= HTP_FIELD_INVALID;
            // Only log once per transaction
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Request field invalid: empty name");
        }
    }

    name_end = colon_pos;

    // Ignore LWS after field-name
    size_t prev = name_end;
    while ((prev > name_start) && (htp_is_lws(data[prev - 1]))) {
        prev--;
        name_end--;

        h->flags |= HTP_FIELD_INVALID;

        if (!(connp->in_tx->flags & HTP_FIELD_INVALID)) {
            connp->in_tx->flags |= HTP_FIELD_INVALID;
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Request field invalid: LWS after name");
        }
    }

    // Value

    value_start = colon_pos;

    // Go over the colon
    if (value_start < len) {
        value_start++;
    }

    // Ignore LWS before field-content
    while ((value_start < len) && (htp_is_lws(data[value_start]))) {
        value_start++;
    }

    // Look for the end of field-content
    value_end = value_start;
    while ((value_end < len) && (data[value_end] != '\0')) value_end++;

    // Ignore LWS after field-content
    prev = value_end - 1;
    while ((prev > value_start) && (htp_is_lws(data[prev]))) {
        prev--;
        value_end--;
    }

    // Check that the header name is a token
    size_t i = name_start;
    while (i < name_end) {
        if (!htp_is_token(data[i])) {
            h->flags |= HTP_FIELD_INVALID;

            if (!(connp->in_tx->flags & HTP_FIELD_INVALID)) {
                connp->in_tx->flags |= HTP_FIELD_INVALID;
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Request header name is not a token");
            }

            break;
        }

        i++;
    }

    // Now extract the name and the value
    h->name = bstr_dup_mem((char *) data + name_start, name_end - name_start);
    h->value = bstr_dup_mem((char *) data + value_start, value_end - value_start);

    return HTP_OK;
}

/**
 * Parse request line as Apache 2.2 does.
 *
 * @param connp
 * @return HTP_OK or HTP_ERROR
 */
int htp_parse_request_line_apache_2_2(htp_connp_t *connp) {
    htp_tx_t *tx = connp->in_tx;
    unsigned char *data = (unsigned char *) bstr_ptr(tx->request_line);
    size_t len = bstr_len(tx->request_line);
    size_t pos = 0;

    // In this implementation we assume the
    // line ends with the first NUL byte.
    if (tx->request_line_nul_offset != -1) {
        len = tx->request_line_nul_offset - 1;
    }

    // The request method starts at the beginning of the
    // line and ends with the first whitespace character.
    while ((pos < len) && (!htp_is_space(data[pos]))) {
        pos++;
    }

    // No, we don't care if the method is empty.

    tx->request_method = bstr_dup_mem((char *) data, pos);

#ifdef HTP_DEBUG
    fprint_raw_data(stderr, __FUNCTION__, (unsigned char *)bstr_ptr(tx->request_method), bstr_len(tx->request_method));
#endif

    tx->request_method_number = htp_convert_method_to_number(tx->request_method);

    // Ignore whitespace after request method. The RFC allows
    // for only one SP, but then suggests any number of SP and HT
    // should be permitted. Apache uses isspace(), which is even
    // more permitting, so that's what we use here.
    while ((pos < len) && (isspace(data[pos]))) {
        pos++;
    }

    size_t start = pos;

    // The URI ends with the first whitespace.
    while ((pos < len) && (!htp_is_space(data[pos]))) {
        pos++;
    }

    tx->request_uri = bstr_dup_mem((char *) data + start, pos - start);

#ifdef HTP_DEBUG
    fprint_raw_data(stderr, __FUNCTION__, (unsigned char *)bstr_ptr(tx->request_uri), bstr_len(tx->request_uri));
#endif

    // Ignore whitespace after URI
    while ((pos < len) && (htp_is_space(data[pos]))) {
        pos++;
    }

    // Is there protocol information available?
    if (pos == len) {
        // No, this looks like a HTTP/0.9 request.
        tx->protocol_is_simple = 1;
        return HTP_OK;
    }

    // The protocol information spreads until the end of the line.
    tx->request_protocol = bstr_dup_mem((char *) data + pos, len - pos);
    tx->request_protocol_number = htp_parse_protocol(tx->request_protocol);

#ifdef HTP_DEBUG
    fprint_raw_data(stderr, __FUNCTION__, (unsigned char *)bstr_ptr(tx->request_protocol), bstr_len(tx->request_protocol));
#endif

    return HTP_OK;
}
