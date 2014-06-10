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

#ifndef HTP_MULTIPART_H
#define	HTP_MULTIPART_H

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Seen a LF line in the payload. LF lines are not allowed, but
 * some clients do use them and some backends do accept them. Mixing
 * LF and CRLF lines within some payload might be unusual.
 */
#define HTP_MULTIPART_LF_LINE                   0x0001

/** Seen a CRLF line in the payload. This is normal and expected. */
#define HTP_MULTIPART_CRLF_LINE                 0x0002

/** Seen LWS after a boundary instance in the body. Unusual. */
#define HTP_MULTIPART_BBOUNDARY_LWS_AFTER       0x0004

/** Seen non-LWS content after a boundary instance in the body. Highly unusual. */
#define HTP_MULTIPART_BBOUNDARY_NLWS_AFTER      0x0008

/**
 * Payload has a preamble part. Might not be that unusual.
 */
#define HTP_MULTIPART_HAS_PREAMBLE              0x0010

/**
 * Payload has an epilogue part. Unusual.
 */
#define HTP_MULTIPART_HAS_EPILOGUE              0x0020

/**
 * The last boundary was seen in the payload. Absence of the last boundary
 * may not break parsing with some (most?) backends, but it means that the payload
 * is not well formed. Can occur if the client gives up, or if the connection is
 * interrupted. Incomplete payloads should be blocked whenever possible.
 */
#define HTP_MULTIPART_SEEN_LAST_BOUNDARY        0x0040

/**
 * There was a part after the last boundary. This is highly irregular
 * and indicative of evasion.
 */
#define HTP_MULTIPART_PART_AFTER_LAST_BOUNDARY  0x0080

/**
 * The payloads ends abruptly, without proper termination. Can occur if the client gives up,
 * or if the connection is interrupted. When this flag is raised, HTP_MULTIPART_PART_INCOMPLETE
 * will also be raised for the part that was only partially processed. (But the opposite may not
 * always be the case -- there are other ways in which a part can be left incomplete.)
 */
#define HTP_MULTIPART_INCOMPLETE                0x0100

/** The boundary in the Content-Type header is invalid. */
#define HTP_MULTIPART_HBOUNDARY_INVALID         0x0200

/**
 * The boundary in the Content-Type header is unusual. This may mean that evasion
 * is attempted, but it could also mean that we have encountered a client that does
 * not do things in the way it should.
 */
#define HTP_MULTIPART_HBOUNDARY_UNUSUAL         0x0400

/**
 * The boundary in the Content-Type header is quoted. This is very unusual,
 * and may be indicative of an evasion attempt.
 */
#define HTP_MULTIPART_HBOUNDARY_QUOTED          0x0800

/** Header folding was used in part headers. Very unusual. */
#define HTP_MULTIPART_PART_HEADER_FOLDING       0x1000

/**
 * A part of unknown type was encountered, which probably means that the part is lacking
 * a Content-Disposition header, or that the header is invalid. Highly unusual.
 */
#define HTP_MULTIPART_PART_UNKNOWN              0x2000

/** There was a repeated part header, possibly in an attempt to confuse the parser. Very unusual. */
#define HTP_MULTIPART_PART_HEADER_REPEATED      0x4000

/** Unknown part header encountered. */
#define HTP_MULTIPART_PART_HEADER_UNKNOWN       0x8000

/** Invalid part header encountered. */
#define HTP_MULTIPART_PART_HEADER_INVALID       0x10000

/** Part type specified in the C-D header is neither MULTIPART_PART_TEXT nor MULTIPART_PART_FILE. */
#define HTP_MULTIPART_CD_TYPE_INVALID           0x20000

/** Content-Disposition part header with multiple parameters with the same name. */
#define HTP_MULTIPART_CD_PARAM_REPEATED         0x40000

/** Unknown Content-Disposition parameter. */
#define HTP_MULTIPART_CD_PARAM_UNKNOWN          0x80000

/** Invalid Content-Disposition syntax. */
#define HTP_MULTIPART_CD_SYNTAX_INVALID         0x100000

/**
 * There is an abruptly terminated part. This can happen when the payload itself is abruptly
 * terminated (in which case HTP_MULTIPART_INCOMPLETE) will be raised. However, it can also
 * happen when a boundary is seen before any part data.
 */
#define HTP_MULTIPART_PART_INCOMPLETE           0x200000

/** A NUL byte was seen in a part header area. */
#define HTP_MULTIPART_NUL_BYTE                  0x400000

/** A collection of flags that all indicate an invalid C-D header. */
#define HTP_MULTIPART_CD_INVALID ( \
    HTP_MULTIPART_CD_TYPE_INVALID | \
    HTP_MULTIPART_CD_PARAM_REPEATED | \
    HTP_MULTIPART_CD_PARAM_UNKNOWN | \
    HTP_MULTIPART_CD_SYNTAX_INVALID )

/** A collection of flags that all indicate an invalid part. */
#define HTP_MULTIPART_PART_INVALID ( \
    HTP_MULTIPART_CD_INVALID | \
    HTP_MULTIPART_NUL_BYTE | \
    HTP_MULTIPART_PART_UNKNOWN | \
    HTP_MULTIPART_PART_HEADER_REPEATED | \
    HTP_MULTIPART_PART_INCOMPLETE | \
    HTP_MULTIPART_PART_HEADER_UNKNOWN | \
    HTP_MULTIPART_PART_HEADER_INVALID )

/** A collection of flags that all indicate an invalid Multipart payload. */
#define HTP_MULTIPART_INVALID ( \
    HTP_MULTIPART_PART_INVALID | \
    HTP_MULTIPART_PART_AFTER_LAST_BOUNDARY | \
    HTP_MULTIPART_INCOMPLETE | \
    HTP_MULTIPART_HBOUNDARY_INVALID )

/** A collection of flags that all indicate an unusual Multipart payload. */
#define HTP_MULTIPART_UNUSUAL ( \
    HTP_MULTIPART_INVALID | \
    HTP_MULTIPART_PART_HEADER_FOLDING | \
    HTP_MULTIPART_BBOUNDARY_NLWS_AFTER | \
    HTP_MULTIPART_HAS_EPILOGUE | \
    HTP_MULTIPART_HBOUNDARY_UNUSUAL \
    HTP_MULTIPART_HBOUNDARY_QUOTED )

/** A collection of flags that all indicate an unusual Multipart payload, with a low sensitivity to irregularities. */
#define HTP_MULTIPART_UNUSUAL_PARANOID ( \
    HTP_MULTIPART_UNUSUAL | \
    HTP_MULTIPART_LF_LINE | \
    HTP_MULTIPART_BBOUNDARY_LWS_AFTER | \
    HTP_MULTIPART_HAS_PREAMBLE )

#define HTP_MULTIPART_MIME_TYPE                 "multipart/form-data"

enum htp_multipart_state_t {
    /** Initial state, after the parser has been created but before the boundary initialized. */
    STATE_INIT = 0,

    /** Testing a potential boundary. */
    STATE_BOUNDARY = 1,

    /** Checking the first byte after a boundary. */
    STATE_BOUNDARY_IS_LAST1 = 2,

    /** Checking the second byte after a boundary. */
    STATE_BOUNDARY_IS_LAST2 = 3,

    /** Consuming linear whitespace after a boundary. */
    STATE_BOUNDARY_EAT_LWS = 4,

    /** Used after a CR byte is detected in STATE_BOUNDARY_EAT_LWS. */
    STATE_BOUNDARY_EAT_LWS_CR = 5,
    
    STATE_DATA_INIT = 6,

    STATE_DATA = 7,
};

typedef struct htp_multipart_parser_t {    
    htp_cfg_t *cfg;

    uint64_t flags;
    
    char *boundary;

    size_t boundary_len;

    enum htp_multipart_state_t parser_state;

    enum htp_multipart_state_t stored_state;   

    int boundary_match_offset;
    
    size_t boundary_match_pos;
    
    size_t boundary_candidate_pos;   
} htp_multipart_parser_t;


// -- Functions --

htp_multipart_parser_t *htp_multipart_create(htp_cfg_t *cfg, bstr *boundary, uint64_t flags);

void htp_multipart_destroy(htp_multipart_parser_t *parser);

htp_status_t htp_multipart_finalize(htp_multipart_parser_t *parser);

htp_status_t htp_multipart_find_boundary(bstr *content_type, bstr **boundary, uint64_t *flags);

htp_status_t htp_multipart_parse(htp_multipart_parser_t *parser, const void *_data, size_t len);

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_MULTIPART_H */

