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

#ifndef _HTP_H
#define	_HTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>

#include "htp_version.h"
#include "htp_core.h"

#include "bstr.h"
#include "htp_base64.h"
#include "htp_config.h"
#include "htp_connection_parser.h"
#include "htp_decompressors.h"
#include "htp_hooks.h"
#include "htp_list.h"
#include "htp_multipart.h"
#include "htp_table.h"
#include "htp_transaction.h"
#include "htp_urlencoded.h"
#include "htp_utf8_decoder.h"

/**
 * Represents a single TCP connection.
 */
struct htp_conn_t {
    /** Client IP address. */
    char *client_addr;

    /** Client port. */
    int client_port;

    /** Server IP address. */
    char *server_addr;

    /** Server port. */
    int server_port;

    /**
     * Transactions carried out on this connection. The list may contain
     * NULL elements when some of the transactions are deleted (and then
     * removed from a connection by calling htp_conn_remove_tx().
     */
    htp_list_t *transactions;

    /** Log messages associated with this connection. */
    htp_list_t *messages;

    /** Parsing flags: HTP_CONN_PIPELINED. */
    uint8_t flags;

    /** When was this connection opened? Can be NULL. */
    htp_time_t open_timestamp;

    /** When was this connection closed? Can be NULL. */
    htp_time_t close_timestamp;

    /** Inbound data counter. */
    int64_t in_data_counter;

    /** Outbound data counter. */
    int64_t out_data_counter;
};

/**
 * Used to represent files that are seen during the processing of HTTP traffic. Most
 * commonly this refers to files seen in multipart/form-data payloads. In addition, PUT
 * request bodies can be treated as files.
 */
struct htp_file_t {
    /** Where did this file come from? Possible values: HTP_FILE_MULTIPART and HTP_FILE_PUT. */
    enum htp_file_source_t source;

    /** File name, as provided (e.g., in the Content-Disposition multipart part header. */
    bstr *filename;   

    /** File length. */
    int64_t len;

    /** The unique filename in which this file is stored on the filesystem, when applicable.*/
    char *tmpname;

    /** The file descriptor used for external storage, or -1 if unused. */
    int fd;
};

/**
 * Represents a chunk of file data.
 */
struct htp_file_data_t {
    /** File information. */
    htp_file_t *file;

    /** Pointer to the data buffer. */
    const unsigned char *data;

    /** Buffer length. */
    size_t len;
};

/**
 * Represents a single log entry.
 */
struct htp_log_t {
    /** The connection parser associated with this log message. */
    htp_connp_t *connp;

    /** The transaction associated with this log message, if any. */
    htp_tx_t *tx;

    /** Log message. */
    const char *msg;

    /** Message level. */
    enum htp_log_level_t level;

    /** Message code. */
    int code;

    /** File in which the code that emitted the message resides. */
    const char *file;

    /** Line number on which the code that emitted the message resides. */
    unsigned int line;
};

/**
 * Represents a single request or response header.
 */
struct htp_header_t {
    /** Header name. */
    bstr *name;

    /** Header value. */
    bstr *value;   

    /** Parsing flags; a combination of: HTP_FIELD_INVALID, HTP_FIELD_FOLDED, HTP_FIELD_REPEATED. */
    uint64_t flags;
};

/**
 * Represents a single request parameter.
 */
struct htp_param_t {
    /** Parameter name. */
    bstr *name;

    /** Parameter value. */
    bstr *value;

    /** Source of the parameter, for example HTP_SOURCE_QUERY_STRING. */
    enum htp_data_source_t source;

    /** Type of the data structure referenced below. */
    enum htp_parser_id_t parser_id;

    /**
     * Pointer to the parser data structure that contains
     * complete information about the parameter. Can be NULL.
     */
    void *parser_data;
};

/**
 * Represents a single HTTP transaction, which is a combination of a request and a response.
 */
struct htp_tx_t {
    /** The connection parser associated with this transaction. */
    htp_connp_t *connp;

    /** The connection to which this transaction belongs. */
    htp_conn_t *conn;   

    /** The configuration structure associated with this transaction. */
    htp_cfg_t *cfg;

    /**
     * Is the configuration structure shared with other transactions or connections? If
     * this field is set to HTP_CONFIG_PRIVATE, the transaction owns the configuration.
     */
    int is_config_shared;

    /** The user data associated with this transaction. */
    void *user_data;
    
    
    // Request fields

    /** Contains a count of how many empty lines were skipped before the request line. */
    unsigned int request_ignored_lines;

    /** The first line of this request. */
    bstr *request_line;      

    /** Request method. */
    bstr *request_method;

    /** Request method, as number. Available only if we were able to recognize the request method. */
    enum htp_method_t request_method_number;

    /**
     * Request URI, raw, as given to us on the request line. This field can take different forms,
     * for example authority for CONNECT methods, absolute URIs for proxy requests, and the query
     * string when one is provided. Use htp_tx_t::parsed_uri if you need to access to specific
     * URI elements. Can be NULL if the request line contains only a request method (which is
     * an extreme case of HTTP/0.9, but passes in practice.
     */
    bstr *request_uri;   

    /** Request protocol, as text. Can be NULL if no protocol was specified. */
    bstr *request_protocol;

    /**
     * Protocol version as a number. Multiply the high version number by 100, then add the low
     * version number. You should prefer to work the pre-defined HTP_PROTOCOL_* constants.
     */
    int request_protocol_number;

    /**
     * Is this request using HTTP/0.9? We need a separate field for this purpose because
     * the protocol version alone is not sufficient to determine if HTTP/0.9 is used. For
     * example, if you submit "GET / HTTP/0.9" to Apache, it will not treat the request
     * as HTTP/0.9.
     */
    int is_protocol_0_9;

    /**
     * This structure holds the individual components parsed out of the request URI, with
     * appropriate normalization and transformation applied, per configuration. No information
     * is added. In extreme cases when no URI is provided on the request line, all fields
     * will be NULL. (Well, except for port_number, which will be -1.) To inspect raw data, use
     * htp_tx_t::request_uri or htp_tx_t::parsed_uri_raw.
     */
    htp_uri_t *parsed_uri;

    /**
     * This structure holds the individual components parsed out of the request URI, but
     * without any modification. The purpose of this field is to allow you to look at the data as it
     * was supplied on the request line. Fields can be NULL, depending on what data was supplied.
     * The port_number field is always -1.
     */
    htp_uri_t *parsed_uri_raw;
    
    /* HTTP 1.1 RFC
     * 
     * 4.3 Message Body
     * 
     * The message-body (if any) of an HTTP message is used to carry the
     * entity-body associated with the request or response. The message-body
     * differs from the entity-body only when a transfer-coding has been
     * applied, as indicated by the Transfer-Encoding header field (section
     * 14.41).
     *
     *     message-body = entity-body
     *                  | <entity-body encoded as per Transfer-Encoding>
     */

    /**
     * The length of the request message-body. In most cases, this value
     * will be the same as request_entity_len. The values will be different
     * if request compression or chunking were applied. In that case,
     * request_message_len contains the length of the request body as it
     * has been seen over TCP; request_entity_len contains length after
     * de-chunking and decompression.
     */
    int64_t request_message_len;

    /**
     * The length of the request entity-body. In most cases, this value
     * will be the same as request_message_len. The values will be different
     * if request compression or chunking were applied. In that case,
     * request_message_len contains the length of the request body as it
     * has been seen over TCP; request_entity_len contains length after
     * de-chunking and decompression.
     */
    int64_t request_entity_len;   

    /** Parsed request headers. */
    htp_table_t *request_headers;   

    /**
     * Request transfer coding. Can be one of HTP_CODING_UNKNOWN (body presence not
     * determined yet), HTP_CODING_IDENTITY, HTP_CODING_CHUNKED, HTP_CODING_NO_BODY,
     * and HTP_CODING_UNRECOGNIZED.
     */
    enum htp_transfer_coding_t request_transfer_coding;

    /** Request body compression. */
    enum htp_content_encoding_t request_content_encoding;

    /**
     * This field contain the request content type when that information is
     * available in request headers. The contents of the field will be converted
     * to lowercase and any parameters (e.g., character set information) removed.
     */
    bstr *request_content_type;

    /**
     * Contains the value specified in the Content-Length header. The value of this
     * field will be -1 from the beginning of the transaction and until request
     * headers are processed. It will stay -1 if the C-L header was not provided,
     * or if the value in it cannot be parsed.
     */
    int64_t request_content_length;

    /**
     * Transaction-specific REQUEST_BODY_DATA hook. Behaves as
     * the configuration hook with the same name.
     */
    htp_hook_t *hook_request_body_data;

    /**
     * Transaction-specific RESPONSE_BODY_DATA hook. Behaves as
     * the configuration hook with the same name.
     */
    htp_hook_t *hook_response_body_data;

    /**
     * Query string URLENCODED parser. Available only
     * when the query string is not NULL and not empty.
     */
    htp_urlenp_t *request_urlenp_query;

    /**
     * Request body URLENCODED parser. Available only when the request body is in the
     * application/x-www-form-urlencoded format and the parser was configured to run.
     */
    htp_urlenp_t *request_urlenp_body;

    /**
     * Request body MULTIPART parser. Available only when the body is in the
     * multipart/form-data format and the parser was configured to run.
     */
    htp_mpartp_t *request_mpartp;

    /** Request parameters. */
    htp_table_t *request_params;

    /** Request cookies */
    htp_table_t *request_cookies;

    /** Authentication type used in the request. */
    enum htp_auth_type_t request_auth_type;

    /** Authentication username. */
    bstr *request_auth_username;

    /** Authentication password. Available only when htp_tx_t::request_auth_type is HTP_AUTH_BASIC. */
    bstr *request_auth_password;

    /**
     * Request hostname. Per the RFC, the hostname will be taken from the Host header
     * when available. If the host information is also available in the URI, it is used
     * instead of whatever might be in the Host header. Can be NULL. This field does
     * not contain port information.
     */
    bstr *request_hostname;

    /**
     * Request port number, if presented. The rules for htp_tx_t::request_host apply. Set to
     * -1 by default.
     */
    int request_port_number;


    // Response fields

    /** How many empty lines did we ignore before reaching the status line? */
    unsigned int response_ignored_lines;

    /** Response line. */
    bstr *response_line;   

    /** Response protocol, as text. Can be NULL. */
    bstr *response_protocol;

    /**
     * Response protocol as number. Available only if we were able to parse the protocol version,
     * HTP_PROTOCOL_INVALID otherwise. HTP_PROTOCOL_UNKNOWN until parsing is attempted.
     */
    int response_protocol_number;

    /**
     * Response status code, as text. Starts as NULL and can remain NULL on
     * an invalid response that does not specify status code.
     */
    bstr *response_status;

    /**
     * Response status code, available only if we were able to parse it, HTP_STATUS_INVALID
     * otherwise. HTP_STATUS_UNKNOWN until parsing is attempted.
     */
    int response_status_number;

    /**
     * This field is set by the protocol decoder with it thinks that the
     * backend server will reject a request with a particular status code.
     */
    int response_status_expected_number;

    /** The message associated with the response status code. Can be NULL. */
    bstr *response_message;

    /** Have we seen the server respond with a 100 response? */
    int seen_100continue;      

    /** Parsed response headers. Contains instances of htp_header_t. */
    htp_table_t *response_headers;   

    /* HTTP 1.1 RFC
     * 
     * 4.3 Message Body
     * 
     * The message-body (if any) of an HTTP message is used to carry the
     * entity-body associated with the request or response. The message-body
     * differs from the entity-body only when a transfer-coding has been
     * applied, as indicated by the Transfer-Encoding header field (section
     * 14.41).
     *
     *     message-body = entity-body
     *                  | <entity-body encoded as per Transfer-Encoding>
     */

    /**
     * The length of the response message-body. In most cases, this value
     * will be the same as response_entity_len. The values will be different
     * if response compression or chunking were applied. In that case,
     * response_message_len contains the length of the response body as it
     * has been seen over TCP; response_entity_len contains the length after
     * de-chunking and decompression.
     */
    int64_t response_message_len;

    /**
     * The length of the response entity-body. In most cases, this value
     * will be the same as response_message_len. The values will be different
     * if request compression or chunking were applied. In that case,
     * response_message_len contains the length of the response body as it
     * has been seen over TCP; response_entity_len contains length after
     * de-chunking and decompression.
     */
    int64_t response_entity_len;

    /**
     * Contains the value specified in the Content-Length header. The value of this
     * field will be -1 from the beginning of the transaction and until response
     * headers are processed. It will stay -1 if the C-L header was not provided,
     * or if the value in it cannot be parsed.
     */
    int64_t response_content_length;
    
    /**
     * Response transfer coding, which indicates if there is a response body,
     * and how it is transported (e.g., as-is, or chunked).
     */
    enum htp_transfer_coding_t response_transfer_coding;

    /**
     * Response body compression, which indicates if compression is used
     * for the response body. This field is an interpretation of the information
     * available in response headers.
     */
    enum htp_content_encoding_t response_content_encoding;

    /**
     * Response body compression processing information, which is related to how
     * the library is going to process (or has processed) a response body. Changing
     * this field mid-processing can influence library actions. For example, setting
     * this field to HTP_COMPRESSION_NONE in a RESPONSE_HEADERS callback will prevent
     * decompression.
     */
    enum htp_content_encoding_t response_content_encoding_processing;
    
    /**
     * This field will contain the response content type when that information
     * is available in response headers. The contents of the field will be converted
     * to lowercase and any parameters (e.g., character set information) removed.
     */
    bstr *response_content_type;

    
    // Common fields

    /**
     * Parsing flags; a combination of: HTP_REQUEST_INVALID_T_E, HTP_INVALID_FOLDING,
     * HTP_REQUEST_SMUGGLING, HTP_MULTI_PACKET_HEAD, and HTP_FIELD_UNPARSEABLE.
     */
    uint64_t flags;

    /** Request progress. */
    enum htp_tx_req_progress_t request_progress;

    /** Response progress. */
    enum htp_tx_res_progress_t response_progress;

    /** Transaction index on the connection. */
    size_t index;
};

/**
 * This structure is used to pass transaction data (for example
 * request and response body buffers) to callbacks.
 */
struct htp_tx_data_t {
    /** Transaction pointer. */
    htp_tx_t *tx;

    /** Pointer to the data buffer. */
    const unsigned char *data;

    /** Buffer length. */
    size_t len;

    /**
     * Indicator if this chunk of data is the last in the series. Currently
     * used only by REQUEST_HEADER_DATA, REQUEST_TRAILER_DATA, RESPONSE_HEADER_DATA,
     * and RESPONSE_TRAILER_DATA callbacks.
     */
    int is_last;
};

/**
 * URI structure. Each of the fields provides access to a single
 * URI element. Where an element is not present in a URI, the
 * corresponding field will be set to NULL or -1, depending on the
 * field type.
 */
struct htp_uri_t {
    /** Scheme, e.g., "http". */
    bstr *scheme;

    /** Username. */
    bstr *username;

    /** Password. */
    bstr *password;

    /** Hostname. */
    bstr *hostname;

    /** Port, as string. */
    bstr *port;

    /**
     * Port, as number. This field will contain HTP_PORT_NONE if there was
     * no port information in the URI and HTP_PORT_INVALID if the port information
     * was invalid (e.g., it's not a number or it falls out of range.
     */
    int port_number;

    /** The path part of this URI. */
    bstr *path;

    /** Query string. */
    bstr *query;

    /**
     * Fragment identifier. This field will rarely be available in a server-side
     * setting, but it's not impossible to see it. */
    bstr *fragment;
};

/**
 * Frees all data contained in the uri, and then the uri itself.
 * 
 * @param[in] uri
 */
void htp_uri_free(htp_uri_t *uri);

/**
 * Allocates and initializes a new htp_uri_t structure.
 *
 * @return New structure, or NULL on memory allocation failure.
 */
htp_uri_t *htp_uri_alloc(void);

/**
 * Creates a new log entry and stores it with the connection. The file and line
 * parameters are typically auto-generated using the HTP_LOG_MARK macro.
*
 * @param[in] connp
 * @param[in] file
 * @param[in] line
 * @param[in] level
 * @param[in] code
 * @param[in] fmt
 * @param[in] ...
 */
void htp_log(htp_connp_t *connp, const char *file, int line, enum htp_log_level_t level, int code, const char *fmt, ...);
    
/**
 * Performs in-place decoding of the input string, according to the configuration specified
 * by cfg and ctx. On output, various flags (HTP_URLEN_*) might be set.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] input
 * @param[out] flags
 *
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_urldecode_inplace(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, bstr *input, uint64_t *flags);

/**
 * Performs in-place decoding of the input string, according to the configuration specified
 * by cfg and ctx. On output, various flags (HTP_URLEN_*) might be set. If something in the
 * input would cause a particular server to respond with an error, the appropriate status
 * code will be set.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] input
 * @param[out] flags
 * @param[out] expected_status_code 0 by default, or status code as necessary
 *
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_urldecode_inplace_ex(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, bstr *input, uint64_t *flags, int *expected_status_code);

/**
 * Returns the LibHTP version string.
 * 
 * @return LibHTP version, for example "LibHTP v0.5.x".
 */
char *htp_get_version(void);

#ifdef __cplusplus
}
#endif

#endif	/* _HTP_H */
