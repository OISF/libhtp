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

#if 0

/**
 *
 */
int htp_header_parse_internal_strict(unsigned char *data, size_t len, htp_header_t *h) {
    size_t name_start, name_end;
    size_t value_start, value_end;

    // Deal with the name first
    name_start = name_end = 0;

    // Find where the header name ends
    while (name_end < len) {
        if (htp_is_lws(data[name_end]) || data[name_end] == ':') break;
        name_end++;
    }

    if (name_end == 0) {
        // Empty header name
        return -1;
    }

    if (name_end == len) {
        // TODO
        return -1;
    }

    // Is there any LWS before colon?
    size_t pos = name_end;
    while (pos < len) {
        if (!htp_is_lws(data[pos])) break;
        pos++;
        // TODO
        // return -1;
    }

    if (pos == len) {
        // TODO
        return -1;
    }

    // The next character must be a colon
    if (data[pos] != ':') {
        // TODO
        return -1;
    }

    // Move over the colon
    pos++;

    // Again, ignore any LWS
    while (pos < len) {
        if (!htp_is_lws(data[pos])) break;
        pos++;
    }

    if (pos == len) {
        // TODO
        return -1;
    }

    value_start = value_end = pos;

    while (value_end < len) {
        if (htp_is_lws(data[value_end])) break;
        value_end++;
    }

    h->name_offset = name_start;
    h->name_len = name_end - name_start;
    h->value_offset = value_start;
    h->value_len = value_end - value_start;

    return 1;
}
 */

/**
 *
 */
htp_header_t *htp_connp_header_parse(htp_connp_t *reqp, unsigned char *data, size_t len) {
    htp_header_t *h = calloc(1, sizeof (htp_header_t));
    if (h == NULL) return NULL;

    // Parse the header line    
    if (reqp->impl_header_parse(data, len, h) < 0) {
        // Invalid header line
        h->is_parsed = 0;
        h->name = bstr_dup_mem(data, len);

        return h;
    }

    // Now extract the name and the value
    h->name = bstr_dup_mem(data + h->name_offset, h->name_len);
    h->value = bstr_dup_mem(data + h->value_offset, h->value_len);
    h->is_parsed = 1;

    // Because header names are case-insensitive, we will convert
    // the name to lowercase to use it as a lookup key.
    h->name_lowercase = bstr_to_lowercase(h->name);

    return h;
}

#endif
