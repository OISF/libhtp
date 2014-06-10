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

#ifndef _HTP_MULTIPART_H
#define	_HTP_MULTIPART_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bstr.h"
#include "htp.h"
#include "htp_table.h"


// Constants and enums.

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

enum htp_multipart_type_t {

    /** Unknown part. */
    MULTIPART_PART_UNKNOWN = 0,

    /** Text (parameter) part. */
    MULTIPART_PART_TEXT = 1,

    /** File part. */
    MULTIPART_PART_FILE = 2,

    /** Free-text part before the first boundary. */
    MULTIPART_PART_PREAMBLE = 3,

    /** Free-text part after the last boundary. */
    MULTIPART_PART_EPILOGUE = 4
};


// Structures

/**
 * Holds multipart parser configuration and state. Private.
 */
typedef struct htp_mpartp_t htp_mpartp_t;

/**
 * Holds information related to a multipart body.
 */
typedef struct htp_multipart_t {
    /** Multipart boundary. */
    char *boundary;

    /** Boundary length. */
    size_t boundary_len;

    /** How many boundaries were there? */
    int boundary_count;   

    /** List of parts, in the order in which they appeared in the body. */
    htp_list_t *parts;

    /** Parsing flags. */
    uint64_t flags;
} htp_multipart_t;

/**
 * Holds information related to a part.
 */
typedef struct htp_multipart_part_t {
    /** Pointer to the parser. */
    htp_mpartp_t *parser;

    /** Part type; see the MULTIPART_PART_* constants. */
    enum htp_multipart_type_t type;

    /** Raw part length (i.e., headers and data). */
    size_t len;
   
    /** Part name, from the Content-Disposition header. Can be NULL. */
    bstr *name;   

    /**
     * Part value; the contents depends on the type of the part:
     * 1) NULL for files; 2) contains complete part contents for
     * preamble and epilogue parts (they have no headers), and
     * 3) data only (headers excluded) for text and unknown parts.
     */
    bstr *value;

    /** Part content type, from the Content-Type header. Can be NULL. */
    bstr *content_type;

    /** Part headers (htp_header_t instances), using header name as the key. */
    htp_table_t *headers;

    /** File name; used only with filename parts. */
    bstr *filename;
} htp_multipart_part_t;


// Functions

/**
 * Creates a new multipart/form-data parser. On a successful invocation,
 * the ownership of the boundary parameter is transferred to the parser.
 *
 * @param[in] cfg
 * @param[in] boundary
 * @param[in] flags
 * @return New parser instance, or NULL on memory allocation failure.
 */
htp_mpartp_t *htp_mpartp_create(htp_cfg_t *cfg, bstr *boundary, uint64_t flags);

/**
 * Looks for boundary in the supplied Content-Type request header. The extracted
 * boundary will be allocated on the heap.
 *
 * @param[in] content_type
 * @param[out] boundary
 * @param[out] multipart_flags Multipart flags, which are not compatible from general LibHTP flags.
 * @return HTP_OK on success (boundary found), HTP_DECLINED if boundary was not found,
 *         and HTP_ERROR on failure. Flags may be set on HTP_OK and HTP_DECLINED. For
 *         example, if a boundary could not be extracted but there is indication that
 *         one is present, HTP_MULTIPART_HBOUNDARY_INVALID will be set.
 */
htp_status_t htp_mpartp_find_boundary(bstr *content_type, bstr **boundary, uint64_t *multipart_flags);

/**
 * Returns the multipart structure created by the parser.
 *
 * @param[in] parser
 * @return The main multipart structure.
 */
htp_multipart_t *htp_mpartp_get_multipart(htp_mpartp_t *parser);

/**
 * Destroys the provided parser.
 *
 * @param[in] parser
 */
void htp_mpartp_destroy(htp_mpartp_t *parser);

/**
 * Finalize parsing.
 *
 * @param[in] parser
 * @returns HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_mpartp_finalize(htp_mpartp_t *parser);

/**
 * Parses a chunk of multipart/form-data data. This function should be called
 * as many times as necessary until all data has been consumed.
 *
 * @param[in] parser
 * @param[in] data
 * @param[in] len
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_mpartp_parse(htp_mpartp_t *parser, const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif	/* _HTP_MULTIPART_H */
