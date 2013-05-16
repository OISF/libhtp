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

#ifndef _HTP_URLENCODED_H
#define	_HTP_URLENCODED_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct htp_urlenp_t htp_urlenp_t;
typedef struct htp_urlen_param_t htp_urlen_param_t;

#define HTP_URLENP_DEFAULT_PARAMS_SIZE  32

#define HTP_URLENP_STATE_KEY            1
#define HTP_URLENP_STATE_VALUE          2

// The MIME type that triggers the parser. Must be lowercase.
#define HTP_URLENCODED_MIME_TYPE        "application/x-www-form-urlencoded"

#include "htp.h"

/**
 * This is the main URLENCODED parser structure. It is used to store
 * parser configuration, temporary parsing data, as well as the parameters.
 */
struct htp_urlenp_t {
    /** The transaction this parser belongs to. */
    htp_tx_t *tx;
    
    /** The character used to separate parameters. Defaults to & and should
     *  not be changed without good reason.
     */
    unsigned char argument_separator;

    /** Whether to perform URL-decoding on parameters. */
    int decode_url_encoding;        

    /** This table contains the list of parameters, indexed by name. */
    htp_table_t *params;

    // Private fields; these are used during the parsing process only
    int _state;
    int _complete;
    bstr *_name;
    bstr_builder_t *_bb;
};

/**
 * Holds one application/x-www-form-urlencoded parameter.
 */
struct htp_urlen_param_t {
    /** Parameter name. */
    bstr *name;
    
    /** Parameter value. */
    bstr *value;
};

htp_urlenp_t *htp_urlenp_create(htp_tx_t *tx);
void htp_urlenp_destroy(htp_urlenp_t *urlenp);

void htp_urlenp_set_argument_separator(htp_urlenp_t *urlenp, unsigned char argument_separator);         
void htp_urlenp_set_decode_url_encoding(htp_urlenp_t *urlenp, int decode_url_encoding);
         
htp_status_t htp_urlenp_parse_partial(htp_urlenp_t *urlenp, const void *data, size_t len);
htp_status_t htp_urlenp_parse_complete(htp_urlenp_t *urlenp, const void *data, size_t len);
htp_status_t htp_urlenp_finalize(htp_urlenp_t *urlenp);

#ifdef __cplusplus
}
#endif

#endif	/* _HTP_URLENCODED_H */

