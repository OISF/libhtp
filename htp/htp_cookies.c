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
 * Parses a single v0 request cookie and places the results into tx->request_cookies.
 *
 * @param[in] connp
 * @param[in] data
 * @param[in] len
 * @return HTP_OK on success, HTP_ERROR on error.
 */
int htp_parse_single_cookie_v0(htp_connp_t *connp, unsigned char *data, size_t len) {
    if (len == 0) return HTP_OK;
    
    size_t pos = 0;

    // Look for '='.
    while ((pos < len) && (data[pos] != '=')) pos++;
    if (pos == 0) return HTP_OK; // Ignore a nameless cookie.

    bstr *name = bstr_dup_mem(data, pos);
    if (name == NULL) return HTP_ERROR;

    bstr *value = NULL;
    if (pos == len) {
        // The cookie is empty.
        value = bstr_dup_c("");
    } else {
        // The cookie is not empty.
        value = bstr_dup_mem(data + pos + 1, len - pos - 1);
    }

    if (value == NULL) {
        bstr_free(name);
        return HTP_ERROR;
    }
    
    htp_table_addn(connp->in_tx->request_cookies, name, value);

    return HTP_OK;
}

/**
 * Parses the Cookie request header in v0 format.
 *
 * @param[in] connp
 * @return HTP_OK on success, HTP_ERROR on error
 */
htp_status_t htp_parse_cookies_v0(htp_connp_t *connp) {
    htp_header_t *cookie_header = htp_table_get_c(connp->in_tx->request_headers, "cookie");
    if (cookie_header == NULL) return HTP_OK;

    // Create a new table to store cookies.
    connp->in_tx->request_cookies = htp_table_create(4);
    if (connp->in_tx->request_cookies == NULL) return HTP_ERROR;

    unsigned char *data = bstr_ptr(cookie_header->value);
    size_t len = bstr_len(cookie_header->value);
    size_t pos = 0;

    while (pos < len) {
        // Ignore whitespace at the beginning.
        while ((pos < len) && (isspace((int)data[pos]))) pos++;
        if (pos == len) return HTP_OK;

        size_t start = pos;

        // Find the end of the cookie.
        while ((pos < len) && (data[pos] != ';')) pos++;

        if (htp_parse_single_cookie_v0(connp, data + start, pos - start) != HTP_OK) {
            return HTP_ERROR;
        }

        // Go over the semicolon.
        if (pos < len) pos++;
    }

    return HTP_OK;
}
