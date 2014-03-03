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

#ifndef HTP_CORE_H
#define	HTP_CORE_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef int htp_status_t;

typedef struct htp_cfg_t htp_cfg_t;
typedef struct htp_conn_t htp_conn_t;
typedef struct htp_connp_t htp_connp_t;
typedef struct htp_file_t htp_file_t;
typedef struct htp_file_data_t htp_file_data_t;
typedef struct htp_header_t htp_header_t;
typedef struct htp_header_line_t htp_header_line_t;
typedef struct htp_log_t htp_log_t;
typedef struct htp_param_t htp_param_t;
typedef struct htp_tx_data_t htp_tx_data_t;
typedef struct htp_tx_t htp_tx_t;
typedef struct htp_uri_t htp_uri_t;
typedef struct timeval htp_time_t;

// Below are all htp_status_t return codes used by LibHTP. Enum is not
// used here to allow applications to define their own codes.

/**
 * The lowest htp_status_t value LibHTP will use internally.
 */
#define HTP_ERROR_RESERVED          -1000

/** General-purpose error code. */
#define HTP_ERROR                   -1

/**
 * No processing or work was done. This is typically used by callbacks
 * to indicate that they were not interested in doing any work in the
 * given context.
 */
#define HTP_DECLINED                0

/** Returned by a function when its work was successfully completed. */
#define HTP_OK                      1

/**
 * Returned when processing a connection stream, after consuming all
 * provided data. The caller should call again with more data.
 */
#define HTP_DATA                    2

/**
 * Returned when processing a connection stream, after encountering
 * a situation where processing needs to continue on the alternate
 * stream (e.g., the inbound parser needs to observe some outbound
 * data). The data provided was not completely consumed. On the next
 * invocation the caller should supply only the data that has not
 * been processed already. Use htp_connp_req_data_consumed() and
 * htp_connp_res_data_consumed() to determine how much of the most
 * recent data chunk was consumed.
 */
#define HTP_DATA_OTHER              3

/**
 * Used by callbacks to indicate that the processing should stop. For example,
 * returning HTP_STOP from a connection callback indicates that LibHTP should
 * stop following that particular connection.
 */
#define HTP_STOP                    4

/**
 * Same as HTP_DATA, but indicates that any non-consumed part of the
 * data chunk should be preserved (buffered) for later.
 */
#define HTP_DATA_BUFFER             5

/**
 * The highest htp_status_t value LibHTP will use internally.
 */
#define HTP_STATUS_RESERVED         1000

/**
 * Enumerates the possible values for authentication type.
 */
enum htp_auth_type_t {
    /**
     * This is the default value that is used before
     * the presence of authentication is determined (e.g.,
     * before request headers are seen).
     */
    HTP_AUTH_UNKNOWN = 0,

    /** No authentication. */
    HTP_AUTH_NONE = 1,

    /** HTTP Basic authentication used. */
    HTP_AUTH_BASIC = 2,

    /** HTTP Digest authentication used. */
    HTP_AUTH_DIGEST = 3,

    /** Unrecognized authentication method. */
    HTP_AUTH_UNRECOGNIZED = 9
};

enum htp_content_encoding_t {
    /**
     * This is the default value, which is used until the presence
     * of content encoding is determined (e.g., before request headers
     * are seen.
     */
    HTP_COMPRESSION_UNKNOWN = 0,

    /** No compression. */
    HTP_COMPRESSION_NONE = 1,

    /** Gzip compression. */
    HTP_COMPRESSION_GZIP = 2,

    /** Deflate compression. */
    HTP_COMPRESSION_DEFLATE = 3
};

/**
 * Enumerates the possible request and response body codings.
 */
enum htp_transfer_coding_t {
    /** Body coding not determined yet. */
    HTP_CODING_UNKNOWN = 0,

    /** No body. */
    HTP_CODING_NO_BODY = 1,

    /** Identity coding is used, which means that the body was sent as is. */
    HTP_CODING_IDENTITY = 2,

    /** Chunked encoding. */
    HTP_CODING_CHUNKED = 3,

    /** We could not recognize the encoding. */
    HTP_CODING_INVALID = 4
};

enum htp_file_source_t {

    HTP_FILE_MULTIPART = 1,

    HTP_FILE_PUT = 2
};

// Various flag bits. Even though we have a flag field in several places
// (header, transaction, connection), these fields are all in the same namespace
// because we may want to set the same flag in several locations. For example, we
// may set HTP_FIELD_FOLDED on the actual folded header, but also on the transaction
// that contains the header. Both uses are useful.

// Connection flags are 8 bits wide.
#define HTP_CONN_PIPELINED                 0x000000001ULL
#define HTP_CONN_HTTP_0_9_EXTRA            0x000000002ULL

// All other flags are 64 bits wide.
#define HTP_FIELD_UNPARSEABLE              0x000000004ULL
#define HTP_FIELD_INVALID                  0x000000008ULL
#define HTP_FIELD_FOLDED                   0x000000010ULL
#define HTP_FIELD_REPEATED                 0x000000020ULL
#define HTP_FIELD_LONG                     0x000000040ULL
#define HTP_FIELD_RAW_NUL                  0x000000080ULL
#define HTP_REQUEST_SMUGGLING              0x000000100ULL
#define HTP_INVALID_FOLDING                0x000000200ULL
#define HTP_REQUEST_INVALID_T_E            0x000000400ULL
#define HTP_MULTI_PACKET_HEAD              0x000000800ULL
#define HTP_HOST_MISSING                   0x000001000ULL
#define HTP_HOST_AMBIGUOUS                 0x000002000ULL
#define HTP_PATH_ENCODED_NUL               0x000004000ULL
#define HTP_PATH_RAW_NUL                   0x000008000ULL
#define HTP_PATH_INVALID_ENCODING          0x000010000ULL
#define HTP_PATH_INVALID                   0x000020000ULL
#define HTP_PATH_OVERLONG_U                0x000040000ULL
#define HTP_PATH_ENCODED_SEPARATOR         0x000080000ULL
#define HTP_PATH_UTF8_VALID                0x000100000ULL /* At least one valid UTF-8 character and no invalid ones. */
#define HTP_PATH_UTF8_INVALID              0x000200000ULL
#define HTP_PATH_UTF8_OVERLONG             0x000400000ULL
#define HTP_PATH_HALF_FULL_RANGE           0x000800000ULL /* Range U+FF00 - U+FFEF detected. */
#define HTP_STATUS_LINE_INVALID            0x001000000ULL
#define HTP_HOSTU_INVALID                  0x002000000ULL /* Host in the URI. */
#define HTP_HOSTH_INVALID                  0x004000000ULL /* Host in the Host header. */
#define HTP_URLEN_ENCODED_NUL              0x008000000ULL
#define HTP_URLEN_INVALID_ENCODING         0x010000000ULL
#define HTP_URLEN_OVERLONG_U               0x020000000ULL
#define HTP_URLEN_HALF_FULL_RANGE          0x040000000ULL /* Range U+FF00 - U+FFEF detected. */
#define HTP_URLEN_RAW_NUL                  0x080000000ULL
#define HTP_REQUEST_INVALID                0x100000000ULL
#define HTP_REQUEST_INVALID_C_L            0x200000000ULL
#define HTP_AUTH_INVALID                   0x400000000ULL

#define HTP_HOST_INVALID ( HTP_HOSTU_INVALID | HTP_HOSTH_INVALID )

// Logging-related constants.
#define HTP_LOG_MARK                 __FILE__,__LINE__

/**
 * Enumerates all log levels.
 */
enum htp_log_level_t {
    HTP_LOG_NONE = 0,
    HTP_LOG_ERROR = 1,
    HTP_LOG_WARNING = 2,
    HTP_LOG_NOTICE = 3,
    HTP_LOG_INFO = 4,
    HTP_LOG_DEBUG = 5,
    HTP_LOG_DEBUG2 = 6
};

/**
 * HTTP methods.
 */
enum htp_method_t {
    /**
     * Used by default, until the method is determined (e.g., before
     * the request line is processed.
     */
    HTP_M_UNKNOWN = 0,
    HTP_M_HEAD = 1,
    HTP_M_GET = 2,
    HTP_M_PUT = 3,
    HTP_M_POST = 4,
    HTP_M_DELETE = 5,
    HTP_M_CONNECT = 6,
    HTP_M_OPTIONS = 7,
    HTP_M_TRACE = 8,
    HTP_M_PATCH = 9,
    HTP_M_PROPFIND = 10,
    HTP_M_PROPPATCH = 11,
    HTP_M_MKCOL = 12,
    HTP_M_COPY = 13,
    HTP_M_MOVE = 14,
    HTP_M_LOCK = 15,
    HTP_M_UNLOCK = 16,
    HTP_M_VERSION_CONTROL = 17,
    HTP_M_CHECKOUT = 18,
    HTP_M_UNCHECKOUT = 19,
    HTP_M_CHECKIN = 20,
    HTP_M_UPDATE = 21,
    HTP_M_LABEL = 22,
    HTP_M_REPORT = 23,
    HTP_M_MKWORKSPACE = 24,
    HTP_M_MKACTIVITY = 25,
    HTP_M_BASELINE_CONTROL = 26,
    HTP_M_MERGE = 27,
    HTP_M_INVALID = 28
};

// A collection of unique parser IDs.
enum htp_parser_id_t {
    /** application/x-www-form-urlencoded parser. */
    HTP_PARSER_URLENCODED = 0,
    
    /** multipart/form-data parser. */
    HTP_PARSER_MULTIPART = 1
};

// Protocol version constants; an enum cannot be
// used here because we allow any properly-formatted protocol
// version (e.g., 1.3), even those that do not actually exist.
#define HTP_PROTOCOL_INVALID        -2
#define HTP_PROTOCOL_UNKNOWN        -1
#define HTP_PROTOCOL_0_9             9
#define HTP_PROTOCOL_1_0             100
#define HTP_PROTOCOL_1_1             101

// A collection of possible data sources.
enum htp_data_source_t {
    /** Embedded in the URL. */
    HTP_SOURCE_URL = 0,

    /** Transported in the query string. */
    HTP_SOURCE_QUERY_STRING = 1,

    /** Cookies. */
    HTP_SOURCE_COOKIE = 2,

    /** Transported in the request body. */
    HTP_SOURCE_BODY = 3
};

#define HTP_STATUS_INVALID           -1
#define HTP_STATUS_UNKNOWN            0

/**
 * Enumerates all stream states. Each connection has two streams, one
 * inbound and one outbound. Their states are tracked separately.
 */
enum htp_stream_state_t {
    HTP_STREAM_NEW = 0,
    HTP_STREAM_OPEN = 1,
    HTP_STREAM_CLOSED = 2,
    HTP_STREAM_ERROR = 3,
    HTP_STREAM_TUNNEL = 4,
    HTP_STREAM_DATA_OTHER = 5,
    HTP_STREAM_STOP = 6,
    HTP_STREAM_DATA = 9
};

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_CORE_H */
