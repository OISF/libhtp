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

#ifndef _HTP_MULTIPART_PRIVATE_H
#define	_HTP_MULTIPART_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "htp_multipart.h"

#define CD_PARAM_OTHER                  0
#define CD_PARAM_NAME                   1
#define CD_PARAM_FILENAME               2

enum htp_part_mode_t {
    /** When in line mode, the parser is handling part headers. */
    MODE_LINE = 0,

    /** When in data mode, the parser is consuming part data. */
    MODE_DATA = 1
};

enum htp_multipart_state_t {
    /** Initial state, after the parser has been created but before the boundary initialized. */
    STATE_INIT = 0,

    /** Processing data, waiting for a new line (which might indicate a new boundary). */
    STATE_DATA = 1,

    /** Testing a potential boundary. */
    STATE_BOUNDARY = 2,

    /** Checking the first byte after a boundary. */
    STATE_BOUNDARY_IS_LAST1 = 3,

    /** Checking the second byte after a boundary. */
    STATE_BOUNDARY_IS_LAST2 = 4,

    /** Consuming linear whitespace after a boundary. */
    STATE_BOUNDARY_EAT_LWS = 5,

    /** Used after a CR byte is detected in STATE_BOUNDARY_EAT_LWS. */
    STATE_BOUNDARY_EAT_LWS_CR = 6
};

struct htp_mpartp_t {
    htp_multipart_t multipart;

    htp_cfg_t *cfg;         

    // Parsing callbacks

    int (*handle_data)(htp_mpartp_t *mpartp, const unsigned char *data,
            size_t len, int line_end);
    int (*handle_boundary)(htp_mpartp_t *mpartp);

    // Internal parsing fields; move into a private structure

    /**
     * Parser state; one of MULTIPART_STATE_* constants.
     */
    enum htp_multipart_state_t parser_state;

    /**
     * Keeps track of the current position in the boundary matching progress.
     * When this field reaches boundary_len, we have a boundary match.
     */
    size_t boundary_match_pos;

    /**
     * Pointer to the part that is currently being processed.
     */
    htp_multipart_part_t *current_part;

    /**
     * This parser consists of two layers: the outer layer is charged with
     * finding parts, and the internal layer handles part data. There is an
     * interesting interaction between the two parsers. Because the
     * outer layer is seeing every line (it has to, in order to test for
     * boundaries), it also effectively also splits input into lines. The
     * inner parser deals with two areas: first is the headers, which are
     * line based, followed by binary data. When parsing headers, the inner
     * parser can reuse the lines identified by the outer parser. In this
     * variable we keep the current parsing mode of the part, which helps
     * us process input data more efficiently. The possible values are
     * MULTIPART_MODE_LINE and MULTIPART_MODE_DATA.
     */
    enum htp_part_mode_t current_part_mode;

    /**
     * Used for buffering when a potential boundary is fragmented
     * across many input data buffers. On a match, the data stored here is
     * discarded. When there is no match, the buffer is processed as data
     * (belonging to the currently active part).
     */
    bstr_builder_t *boundary_pieces;

    bstr_builder_t *part_header_pieces;

    bstr *pending_header_line;

    /**
     * Stores text part pieces until the entire part is seen, at which
     * point the pieces are assembled into a single buffer, and the
     * builder cleared.
     */
    bstr_builder_t *part_data_pieces;

    /**
     * The offset of the current boundary candidate, relative to the most
     * recent data chunk (first unprocessed chunk of data).
     */
    size_t boundary_candidate_pos;

    /**
     * When we encounter a CR as the last byte in a buffer, we don't know
     * if the byte is part of a CRLF combination. If it is, then the CR
     * might be a part of a boundary. But if it is not, it's current
     * part's data. Because we know how to handle everything before the
     * CR, we do, and we use this flag to indicate that a CR byte is
     * effectively being buffered. This is probably a case of premature
     * optimization, but I am going to leave it in for now.
     */
    int cr_aside;

    /**
     * When set, indicates that this parser no longer owns names and
     * values of MULTIPART_PART_TEXT parts. It is used to avoid data
     * duplication when the parser is used by LibHTP internally.
     */
    int gave_up_data;
};

htp_status_t htp_mpartp_run_request_file_data_hook(htp_multipart_part_t *part, const unsigned char *data, size_t len);

htp_status_t htp_mpart_part_process_headers(htp_multipart_part_t *part);

htp_status_t htp_mpartp_parse_header(htp_multipart_part_t *part, const unsigned char *data, size_t len);

htp_status_t htp_mpart_part_handle_data(htp_multipart_part_t *part, const unsigned char *data, size_t len, int is_line);

int htp_mpartp_is_boundary_character(int c);

htp_multipart_part_t *htp_mpart_part_create(htp_mpartp_t *parser);

htp_status_t htp_mpart_part_finalize_data(htp_multipart_part_t *part);

void htp_mpart_part_destroy(htp_multipart_part_t *part, int gave_up_data);

htp_status_t htp_mpart_part_parse_c_d(htp_multipart_part_t *part);

#ifdef __cplusplus
}
#endif

#endif	/* _HTP_MULTIPART_PRIVATE_H */
