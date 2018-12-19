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
 * Determines protocol number from a textual representation (i.e., "HTTP/1.1"). This
 * function will only understand a properly formatted protocol information. It does
 * not try to be flexible.
 * 
 * @param[in] protocol
 * @return Protocol version or PROTOCOL_UNKNOWN.
 */
int htp_parse_protocol(bstr *protocol) {
    if (protocol == NULL) return HTP_PROTOCOL_INVALID;
    
    // TODO This function uses a very strict approach to parsing, whereas
    //      browsers will typically be more flexible, allowing whitespace
    //      before and after the forward slash, as well as allowing leading
    //      zeroes in the numbers. We should be able to parse such malformed
    //      content correctly (but emit a warning).
    if (bstr_len(protocol) == 8) {
        unsigned char *ptr = bstr_ptr(protocol);
        if ((ptr[0] == 'H') && (ptr[1] == 'T') && (ptr[2] == 'T') && (ptr[3] == 'P')
            && (ptr[4] == '/') && (ptr[6] == '.')) {
            // Check the version numbers
            if (ptr[5] == '0') {
                if (ptr[7] == '9') {
                    return HTP_PROTOCOL_0_9;
                }
            } else if (ptr[5] == '1') {
                if (ptr[7] == '0') {
                    return HTP_PROTOCOL_1_0;
                } else if (ptr[7] == '1') {
                    return HTP_PROTOCOL_1_1;
                }
            }
        }
    }

    return HTP_PROTOCOL_INVALID;
}

/**
 * Determines the numerical value of a response status given as a string.
 *
 * @param[in] status
 * @return Status code on success, or HTP_STATUS_INVALID on error.
 */
int htp_parse_status(bstr *status) {
    int64_t r = htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(status), bstr_len(status), 10);
    if (r >= HTP_VALID_STATUS_MIN && r <= HTP_VALID_STATUS_MAX) {
        return (int)r;
    } else {
        return HTP_STATUS_INVALID;
    }
}

/**
 * Parses Digest Authorization request header.
 *
 * @param[in] connp
 * @param[in] auth_header
 */
int htp_parse_authorization_digest(htp_connp_t *connp, htp_header_t *auth_header) {    
    // Extract the username
    int i = bstr_index_of_c(auth_header->value, "username=");
    if (i == -1) return HTP_DECLINED;

    unsigned char *data = bstr_ptr(auth_header->value);
    size_t len = bstr_len(auth_header->value);
    size_t pos = i + 9;

    // Ignore whitespace
    while ((pos < len) && (isspace((int) data[pos]))) pos++;   
    if (pos == len) return HTP_DECLINED;

    if (data[pos] != '"') return HTP_DECLINED;

    return htp_extract_quoted_string_as_bstr(data + pos, len - pos, &(connp->in_tx->request_auth_username), NULL);
}

/**
 * Parses Basic Authorization request header.
 * 
 * @param[in] connp
 * @param[in] auth_header
 */
int htp_parse_authorization_basic(htp_connp_t *connp, htp_header_t *auth_header) {
    unsigned char *data = bstr_ptr(auth_header->value);
    size_t len = bstr_len(auth_header->value);
    size_t pos = 5;

    // Ignore whitespace
    while ((pos < len) && (isspace((int) data[pos]))) pos++;
    if (pos == len) return HTP_DECLINED;

    // Decode base64-encoded data
    bstr *decoded = htp_base64_decode_mem(data + pos, len - pos);
    if (decoded == NULL) return HTP_ERROR;

    // Now extract the username and password
    int i = bstr_index_of_c(decoded, ":");
    if (i == -1) {
        bstr_free(decoded);    
        return HTP_DECLINED;
    }

    connp->in_tx->request_auth_username = bstr_dup_ex(decoded, 0, i);
    if (connp->in_tx->request_auth_username == NULL) {
        bstr_free(decoded);
        return HTP_ERROR;
    }
    
    connp->in_tx->request_auth_password = bstr_dup_ex(decoded, i + 1, bstr_len(decoded) - i - 1);
    if (connp->in_tx->request_auth_password == NULL) {
        bstr_free(decoded);
        bstr_free(connp->in_tx->request_auth_username);
        return HTP_ERROR;
    }

    bstr_free(decoded);

    return HTP_OK;
}

/**
 * Parses Authorization request header.
 *
 * @param[in] connp
 */
int htp_parse_authorization(htp_connp_t *connp) {
    htp_header_t *auth_header = htp_table_get_c(connp->in_tx->request_headers, "authorization");
    if (auth_header == NULL) {
        connp->in_tx->request_auth_type = HTP_AUTH_NONE;
        return HTP_OK;
    }

    // TODO Need a flag to raise when failing to parse authentication headers.

    if (bstr_begins_with_c_nocase(auth_header->value, "basic")) {
        // Basic authentication
        connp->in_tx->request_auth_type = HTP_AUTH_BASIC;
        return htp_parse_authorization_basic(connp, auth_header);
    } else if (bstr_begins_with_c_nocase(auth_header->value, "digest")) {
        // Digest authentication
        connp->in_tx->request_auth_type = HTP_AUTH_DIGEST;
        return htp_parse_authorization_digest(connp, auth_header);
    } else {
        // Unrecognized authentication method
        connp->in_tx->request_auth_type = HTP_AUTH_UNRECOGNIZED;        
    }

    return HTP_OK;
}
