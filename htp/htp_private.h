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

#ifndef _HTP_PRIVATE_H
#define	_HTP_PRIVATE_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__cplusplus) && !defined(__STDC_FORMAT_MACROS)
/* C99 requires that inttypes.h only exposes PRI* macros
 * for C++ implementations if this is defined: */
#define __STDC_FORMAT_MACROS
#endif

#include <ctype.h>
#include <errno.h>
#include <iconv.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "htp.h"
#include "htp_config_private.h"
#include "htp_connection_parser_private.h"
#include "htp_connection_private.h"
#include "htp_list_private.h"
#include "htp_multipart_private.h"
#include "htp_table_private.h"

#ifndef CR
#define CR '\r'
#endif

#ifndef LF
#define LF '\n'
#endif

#define HTP_FIELD_LIMIT_HARD               18000
#define HTP_FIELD_LIMIT_SOFT               9000

#define HTP_VALID_STATUS_MIN                100
#define HTP_VALID_STATUS_MAX                999
       
// Parser states, in the order in which they are
// used as a single transaction is processed.

htp_status_t htp_connp_REQ_IDLE(htp_connp_t *connp);
htp_status_t htp_connp_REQ_LINE(htp_connp_t *connp);
htp_status_t htp_connp_REQ_LINE_complete(htp_connp_t *connp);
htp_status_t htp_connp_REQ_PROTOCOL(htp_connp_t *connp);
htp_status_t htp_connp_REQ_HEADERS(htp_connp_t *connp);
htp_status_t htp_connp_REQ_CONNECT_CHECK(htp_connp_t *connp);
htp_status_t htp_connp_REQ_CONNECT_WAIT_RESPONSE(htp_connp_t *connp);
htp_status_t htp_connp_REQ_CONNECT_PROBE_DATA(htp_connp_t *connp);
htp_status_t htp_connp_REQ_BODY_DETERMINE(htp_connp_t *connp);
htp_status_t htp_connp_REQ_BODY_IDENTITY(htp_connp_t *connp);
htp_status_t htp_connp_REQ_BODY_CHUNKED_LENGTH(htp_connp_t *connp);
htp_status_t htp_connp_REQ_BODY_CHUNKED_DATA(htp_connp_t *connp);
htp_status_t htp_connp_REQ_BODY_CHUNKED_DATA_END(htp_connp_t *connp);
htp_status_t htp_connp_REQ_FINALIZE(htp_connp_t *connp);
htp_status_t htp_connp_REQ_IGNORE_DATA_AFTER_HTTP_0_9(htp_connp_t *connp);

htp_status_t htp_connp_RES_IDLE(htp_connp_t *connp);
htp_status_t htp_connp_RES_LINE(htp_connp_t *connp);
htp_status_t htp_connp_RES_HEADERS(htp_connp_t *connp);
htp_status_t htp_connp_RES_BODY_DETERMINE(htp_connp_t *connp);
htp_status_t htp_connp_RES_BODY_IDENTITY_CL_KNOWN(htp_connp_t *connp);
htp_status_t htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE(htp_connp_t *connp);
htp_status_t htp_connp_RES_BODY_CHUNKED_LENGTH(htp_connp_t *connp);
htp_status_t htp_connp_RES_BODY_CHUNKED_DATA(htp_connp_t *connp);
htp_status_t htp_connp_RES_BODY_CHUNKED_DATA_END(htp_connp_t *connp);
htp_status_t htp_connp_RES_FINALIZE(htp_connp_t *connp);

// Parsing functions

htp_status_t htp_parse_request_line_generic(htp_connp_t *connp);
htp_status_t htp_parse_request_line_generic_ex(htp_connp_t *connp, int nul_terminates);
htp_status_t htp_parse_request_header_generic(htp_connp_t *connp, htp_header_t *h, unsigned char *data, size_t len);
htp_status_t htp_process_request_header_generic(htp_connp_t *, unsigned char *data, size_t len);

htp_status_t htp_parse_request_line_apache_2_2(htp_connp_t *connp);
htp_status_t htp_process_request_header_apache_2_2(htp_connp_t *, unsigned char *data, size_t len);

htp_status_t htp_parse_response_line_generic(htp_connp_t *connp);
htp_status_t htp_parse_response_header_generic(htp_connp_t *connp, htp_header_t *h, unsigned char *data, size_t len);
htp_status_t htp_process_response_header_generic(htp_connp_t *connp, unsigned char *data, size_t len);


// Private transaction functions

htp_status_t htp_tx_state_response_complete_ex(htp_tx_t *tx, int hybrid_mode);


// Utility functions

int htp_convert_method_to_number(bstr *);
int htp_is_lws(int c);
int htp_is_separator(int c);
int htp_is_text(int c);
int htp_is_token(int c);
int htp_chomp(unsigned char *data, size_t *len);
int htp_is_space(int c);

int htp_parse_protocol(bstr *protocol);

int htp_is_line_empty(unsigned char *data, size_t len);
int htp_is_line_whitespace(unsigned char *data, size_t len);

int htp_connp_is_line_folded(unsigned char *data, size_t len);
int htp_is_folding_char(int c);
int htp_connp_is_line_terminator(htp_connp_t *connp, unsigned char *data, size_t len);
int htp_connp_is_line_ignorable(htp_connp_t *connp, unsigned char *data, size_t len);

int htp_parse_uri(bstr *input, htp_uri_t **uri);
htp_status_t htp_parse_hostport(bstr *authority, bstr **hostname, bstr **port, int *port_number, int *invalid);
htp_status_t htp_parse_header_hostport(bstr *authority, bstr **hostname, bstr **port, int *port_number, uint64_t *flags);
int htp_validate_hostname(bstr *hostname);
int htp_parse_uri_hostport(htp_connp_t *connp, bstr *input, htp_uri_t *uri);
int htp_normalize_parsed_uri(htp_tx_t *tx, htp_uri_t *parsed_uri_incomplete, htp_uri_t *parsed_uri);
bstr *htp_normalize_hostname_inplace(bstr *input);
void htp_replace_hostname(htp_connp_t *connp, htp_uri_t *parsed_uri, bstr *hostname);
int htp_is_uri_unreserved(unsigned char c);

int htp_decode_path_inplace(htp_tx_t *tx, bstr *path);

 int htp_prenormalize_uri_path_inplace(bstr *s, int *flags, int case_insensitive, int backslash, int decode_separators, int remove_consecutive);
void htp_normalize_uri_path_inplace(bstr *s);

void htp_utf8_decode_path_inplace(htp_cfg_t *cfg, htp_tx_t *tx, bstr *path);
void htp_utf8_validate_path(htp_tx_t *tx, bstr *path);

int64_t htp_parse_content_length(bstr *b);
int64_t htp_parse_chunked_length(unsigned char *data, size_t len);
int64_t htp_parse_positive_integer_whitespace(unsigned char *data, size_t len, int base);
int htp_parse_status(bstr *status);
int htp_parse_authorization_digest(htp_connp_t *connp, htp_header_t *auth_header);
int htp_parse_authorization_basic(htp_connp_t *connp, htp_header_t *auth_header);

void htp_print_log(FILE *stream, htp_log_t *log);

void fprint_bstr(FILE *stream, const char *name, bstr *b);
void fprint_raw_data(FILE *stream, const char *name, const void *data, size_t len);
void fprint_raw_data_ex(FILE *stream, const char *name, const void *data, size_t offset, size_t len);

char *htp_connp_in_state_as_string(htp_connp_t *connp);
char *htp_connp_out_state_as_string(htp_connp_t *connp);
char *htp_tx_request_progress_as_string(htp_tx_t *tx);
char *htp_tx_response_progress_as_string(htp_tx_t *tx);

bstr *htp_unparse_uri_noencode(htp_uri_t *uri);

int htp_treat_response_line_as_body(const uint8_t *data, size_t len);

htp_status_t htp_req_run_hook_body_data(htp_connp_t *connp, htp_tx_data_t *d);
htp_status_t htp_res_run_hook_body_data(htp_connp_t *connp, htp_tx_data_t *d);

htp_status_t htp_ch_urlencoded_callback_request_body_data(htp_tx_data_t *d);
htp_status_t htp_ch_urlencoded_callback_request_headers(htp_tx_t *tx);
htp_status_t htp_ch_urlencoded_callback_request_line(htp_tx_t *tx);
htp_status_t htp_ch_multipart_callback_request_body_data(htp_tx_data_t *d);
htp_status_t htp_ch_multipart_callback_request_headers(htp_tx_t *tx);

htp_status_t htp_php_parameter_processor(htp_param_t *p);

int htp_transcode_params(htp_connp_t *connp, htp_table_t **params, int destroy_old);
int htp_transcode_bstr(iconv_t cd, bstr *input, bstr **output);

int htp_parse_single_cookie_v0(htp_connp_t *connp, unsigned char *data, size_t len);
int htp_parse_cookies_v0(htp_connp_t *connp);
int htp_parse_authorization(htp_connp_t *connp);

htp_status_t htp_extract_quoted_string_as_bstr(unsigned char *data, size_t len, bstr **out, size_t *endoffset);

htp_header_t *htp_connp_header_parse(htp_connp_t *, unsigned char *, size_t);

htp_status_t htp_parse_ct_header(bstr *header, bstr **ct);

htp_status_t htp_connp_req_receiver_finalize_clear(htp_connp_t *connp);
htp_status_t htp_connp_res_receiver_finalize_clear(htp_connp_t *connp);

htp_status_t htp_tx_finalize(htp_tx_t *tx);

int htp_tx_is_complete(htp_tx_t *tx);

htp_status_t htp_tx_state_request_complete_partial(htp_tx_t *tx);

void htp_connp_tx_remove(htp_connp_t *connp, htp_tx_t *tx);

void htp_tx_destroy_incomplete(htp_tx_t *tx);

htp_status_t htp_tx_req_process_body_data_ex(htp_tx_t *tx, const void *data, size_t len);
htp_status_t htp_tx_res_process_body_data_ex(htp_tx_t *tx, const void *data, size_t len);

htp_status_t htp_tx_urldecode_uri_inplace(htp_tx_t *tx, bstr *input);
htp_status_t htp_tx_urldecode_params_inplace(htp_tx_t *tx, bstr *input);

void htp_connp_destroy_decompressors(htp_connp_t *connp);

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _HTP_PRIVATE_H */

