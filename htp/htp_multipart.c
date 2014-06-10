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

#include "htp_private.h"

/**
 * @file
 * @author Ivan Ristic <ivanr@webkreator.com>
 */

static void htp_multipart_validate_boundary(bstr *boundary, uint64_t *flags);
static void htp_multipart_validate_content_type(bstr *content_type, uint64_t *flags);

static htp_status_t htp_multipart_init_boundary(htp_multipart_parser_t *parser, unsigned char *data, size_t len) {
    if ((parser == NULL) || (data == NULL)) return HTP_ERROR;

    // Copy the boundary and convert it to lowercase.

    parser->boundary_len = len + 4;
    parser->boundary = malloc(parser->boundary_len + 1);
    if (parser->boundary == NULL) return HTP_ERROR;

    parser->boundary[0] = CR;
    parser->boundary[1] = LF;
    parser->boundary[2] = '-';
    parser->boundary[3] = '-';

    for (size_t i = 0; i < len; i++) {
        parser->boundary[i + 4] = data[i];
    }

    parser->boundary[parser->boundary_len] = '\0';

    // We're starting in boundary-matching mode. The first boundary can appear without the
    // CRLF, and our starting state expects that. If we encounter non-boundary data, the
    // state will switch to data mode. Then, if the data is CRLF or LF, we will go back
    // to boundary matching. Thus, we handle all the possibilities.

    parser->parser_state = STATE_BOUNDARY;
    parser->stored_state = STATE_DATA;
    parser->check_for_boundary_start = 1;
    parser->boundary_match_pos = 2;

    return HTP_OK;
}

htp_multipart_parser_t *htp_multipart_create(htp_cfg_t *cfg, bstr *boundary, uint64_t flags) {
    if ((cfg == NULL) || (boundary == NULL)) return NULL;

    htp_multipart_parser_t *parser = calloc(1, sizeof (htp_multipart_parser_t));
    if (parser == NULL) return NULL;

    parser->cfg = cfg;
    parser->flags = flags;
    parser->parser_state = STATE_INIT;    

    // Initialize the boundary.
    htp_status_t rc = htp_multipart_init_boundary(parser, bstr_ptr(boundary), bstr_len(boundary));
    if (rc != HTP_OK) {
        htp_multipart_destroy(parser);
        return NULL;
    }

    // On success, the ownership of the boundary parameter
    // is transferred to us. We made a copy, and so we
    // don't need it any more.
    bstr_free(boundary);

    return parser;
}

void htp_multipart_destroy(htp_multipart_parser_t *parser) {
    if (parser == NULL) return;

    if (parser->boundary != NULL) {
        free(parser->boundary);
    }      

    free(parser);
}

htp_status_t htp_multipart_finalize(htp_multipart_parser_t *parser) {    

    return HTP_OK;
}

htp_status_t htp_multipart_find_boundary(bstr *content_type, bstr **boundary, uint64_t *flags) {
    if ((content_type == NULL) || (boundary == NULL) || (flags == NULL)) return HTP_ERROR;

    // Our approach is to ignore the MIME type and instead just look for
    // the boundary. This approach is more reliable in the face of various
    // evasion techniques that focus on submitting invalid MIME types.

    // Reset flags.
    *flags = 0;

    // Look for the boundary, case insensitive.
    int i = bstr_index_of_c_nocase(content_type, "boundary");
    if (i == -1) return HTP_DECLINED;

    unsigned char *data = bstr_ptr(content_type) + i + 8;
    size_t len = bstr_len(content_type) - i - 8;

    // Look for the boundary value.
    size_t pos = 0;
    while ((pos < len) && (data[pos] != '=')) {
        if (htp_is_space(data[pos])) {
            // It is unusual to see whitespace before the equals sign.
            *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;
        } else {
            // But seeing a non-whitespace character may indicate evasion.
            *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
        }

        pos++;
    }

    if (pos >= len) {
        // No equals sign in the header.
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
        return HTP_DECLINED;
    }

    // Go over the '=' character.
    pos++;

    // Ignore any whitespace after the equals sign.
    while ((pos < len) && (htp_is_space(data[pos]))) {
        if (htp_is_space(data[pos])) {
            // It is unusual to see whitespace after
            // the equals sign.
            *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;
        }

        pos++;
    }

    if (pos >= len) {
        // No value after the equals sign.
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
        return HTP_DECLINED;
    }

    if (data[pos] == '"') {
        // Quoted boundary.

        // Possibly not very unusual, but let's see.
        *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;

        pos++; // Over the double quote.
        size_t startpos = pos; // Starting position of the boundary.

        // Look for the terminating double quote.
        while ((pos < len) && (data[pos] != '"')) pos++;

        if (pos >= len) {
            // Ran out of space without seeing
            // the terminating double quote.
            *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;

            // Include the starting double quote in the boundary.
            startpos--;
        }

        *boundary = bstr_dup_mem(data + startpos, pos - startpos);
        if (*boundary == NULL) return HTP_ERROR;

        pos++; // Over the double quote.
    } else {
        // Boundary not quoted.

        size_t startpos = pos;

        // Find the end of the boundary. For the time being, we replicate
        // the behavior of PHP 5.4.x. This may result with a boundary that's
        // closer to what would be accepted in real life. Our subsequent
        // checks of boundary characters will catch irregularities.
        while ((pos < len) && (data[pos] != ',') && (data[pos] != ';') && (!htp_is_space(data[pos]))) pos++;

        *boundary = bstr_dup_mem(data + startpos, pos - startpos);
        if (*boundary == NULL) return HTP_ERROR;
    }

    // Check for a zero-length boundary.
    if (bstr_len(*boundary) == 0) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
        return HTP_DECLINED;
    }

    // Allow only whitespace characters after the boundary.
    int seen_space = 0, seen_non_space = 0;

    while (pos < len) {
        if (!htp_is_space(data[pos])) {
            seen_non_space = 1;
        } else {
            seen_space = 1;
        }

        pos++;
    }

    // Raise INVALID if we see any non-space characters,
    // but raise UNUSUAL if we see _only_ space characters.
    if (seen_non_space) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
    } else if (seen_space) {
        *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;
    }

    #ifdef HTP_DEBUG
    fprint_bstr(stderr, "Multipart boundary", *boundary);
    #endif

    // Validate boundary characters.
    htp_multipart_validate_boundary(*boundary, flags);

    // Correlate with the MIME type. This might be a tad too
    // sensitive because it may catch non-browser access with sloppy
    // implementations, but let's go with it for now.
    if (bstr_begins_with_c(content_type, "multipart/form-data;") == 0) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
    }

    htp_multipart_validate_content_type(content_type, flags);

    return HTP_OK;
}


htp_status_t htp_multipart_parse(htp_multipart_parser_t *parser, const void *_data, size_t len) {
    unsigned char *data = (unsigned char *) _data;

    size_t pos = 0;

    while (pos < len) {
        int c = data[pos];

        if ((parser->parser_state >= STATE_DATA)&&(parser->check_for_boundary_start)) {
            if (c == CR) {
                parser->stored_state = parser->parser_state;
                parser->boundary_candidate_pos = pos;
                parser->boundary_match_offset = 0;
                parser->boundary_match_pos = 1;
                parser->parser_state = STATE_BOUNDARY;
                pos++;
                continue;
            } else if (c == LF) {
                parser->stored_state = parser->parser_state;
                parser->boundary_candidate_pos = pos;
                parser->boundary_match_offset = 1;
                parser->boundary_match_pos = 2;
                parser->parser_state = STATE_BOUNDARY;
                pos++;
                continue;
            }
        }

        switch(parser->parser_state) {

            case STATE_INIT :
                printf("Invalid state: STATE_INIT\n");
                return HTP_ERROR;

            case STATE_BOUNDARY :
                printf("boundary_match_pos %i\n", parser->boundary_match_pos);

                if (c == parser->boundary[parser->boundary_match_pos]) {
                    parser->boundary_match_pos++;
                    pos++;

                    if (parser->boundary_match_pos == parser->boundary_len) {
                        parser->parser_state = STATE_BOUNDARY_IS_LAST1;
                    }
                } else {
                    printf("Boundary byte MISMATCH: %i %c\n", c, c);
                    parser->parser_state = parser->stored_state;
                    parser->check_for_boundary_start = 0;
                    htp_multipart_parse(parser, parser->boundary + parser->boundary_match_offset, parser->boundary_match_pos - parser->boundary_match_offset);
                    parser->check_for_boundary_start = 1;
                    continue;
                }
                break;

            case STATE_BOUNDARY_IS_LAST1 :
                if (c == '-') {
                    pos++;
                    parser->parser_state = STATE_BOUNDARY_IS_LAST2;
                } else {
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS;
                }
                break;

            case STATE_BOUNDARY_IS_LAST2 :
                if (c == '-') {
                    pos++;
                    // TODO last boundary
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS;
                } else {
                    // TOOD Flag: invalid boundary termination
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS;
                }
                break;

            case STATE_BOUNDARY_EAT_LWS:
                if (c == CR) {
                    pos++;
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS_CR;
                } else if (c == LF) {
                    // LF line ending; we're done with the boundary.
                    pos++;
                    parser->parser_state = STATE_DATA;
                    parser->check_for_boundary_start = 1;
                } else {
                    if (htp_is_lws(c)) {
                        // Linear white space is allowed here.
                        // XXX
                        // parser->multipart.flags |= HTP_MULTIPART_BBOUNDARY_LWS_AFTER;
                        pos++;
                    } else {
                        // Unexpected byte; consume, but remain in the same state.
                        // XXX
                        // parser->multipart.flags |= HTP_MULTIPART_BBOUNDARY_NLWS_AFTER;
                        pos++;
                    }
                }
                break;

            case STATE_BOUNDARY_EAT_LWS_CR:
                if (c == LF) {
                    // CRLF line ending; we're done with the boundary.
                    pos++;
                    parser->parser_state = STATE_DATA;
                    parser->check_for_boundary_start = 1;
                } else {
                    // Expecting LF but got something else; continue until we see the end of the line.
                    // TOOD Flag: invalid boundary termination
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS;
                }
                break;

            default:
                printf("Data byte: %i %c\n", c, c);
                pos++;
                break;
        }
    }

    return HTP_OK;
}

static void htp_multipart_validate_boundary(bstr *boundary, uint64_t *flags) {
    /*

    RFC 1341:

    The only mandatory parameter for the multipart  Content-Type
    is  the  boundary  parameter,  which  consists  of  1  to 70
    characters from a set of characters known to be very  robust
    through  email  gateways,  and  NOT ending with white space.
    (If a boundary appears to end with white  space,  the  white
    space  must be presumed to have been added by a gateway, and
    should  be  deleted.)   It  is  formally  specified  by  the
    following BNF:

    boundary := 0*69<bchars> bcharsnospace

    bchars := bcharsnospace / " "

    bcharsnospace :=    DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_"
                          / "," / "-" / "." / "/" / ":" / "=" / "?"
     */

    /*
     Chrome: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT4AfwQCOgIxNVwlD
    Firefox: Content-Type: multipart/form-data; boundary=---------------------------21071316483088
       MSIE: Content-Type: multipart/form-data; boundary=---------------------------7dd13e11c0452
      Opera: Content-Type: multipart/form-data; boundary=----------2JL5oh7QWEDwyBllIRc7fh
     Safari: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryre6zL3b0BelnTY5S
     */

    unsigned char *data = bstr_ptr(boundary);
    size_t len = bstr_len(boundary);

    // The RFC allows up to 70 characters. In real life,
    // boundaries tend to be shorter.
    if ((len == 0) || (len > 70)) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
    }

    // Check boundary characters. This check is stricter than the
    // RFC, which seems to allow many separator characters.
    size_t pos = 0;
    while (pos < len) {
        if (!(((data[pos] >= '0') && (data[pos] <= '9'))
                || ((data[pos] >= 'a') && (data[pos] <= 'z'))
                || ((data[pos] >= 'A') && (data[pos] <= 'Z'))
                || (data[pos] == '-'))) {

            switch (data[pos]) {
                case '\'':
                case '(':
                case ')':
                case '+':
                case '_':
                case ',':
                case '.':
                case '/':
                case ':':
                case '=':
                case '?':
                    // These characters are allowed by the RFC, but not common.
                    *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;
                    break;

                default:
                    // Invalid character.
                    *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
                    break;
            }
        }

        pos++;
    }
}

static void htp_multipart_validate_content_type(bstr *content_type, uint64_t *flags) {
    unsigned char *data = bstr_ptr(content_type);
    size_t len = bstr_len(content_type);
    size_t counter = 0;

    while (len > 0) {
        int i = bstr_util_mem_index_of_c_nocase(data, len, "boundary");
        if (i == -1) break;

        data = data + i;
        len = len - i;

        // In order to work around the fact that WebKit actually uses
        // the word "boundary" in their boundary, we also require one
        // equals character the follow the words.
        // "multipart/form-data; boundary=----WebKitFormBoundaryT4AfwQCOgIxNVwlD"
        if (memchr(data, '=', len) == NULL) break;

        counter++;

        // Check for case variations.
        for (size_t j = 0; j < 8; j++) {
            if (!((*data >= 'a') && (*data <= 'z'))) {
                *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
            }

            data++;
            len--;
        }
    }

    // How many boundaries have we seen?
    if (counter > 1) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
    }
}
