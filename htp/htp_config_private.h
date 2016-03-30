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

#ifndef HTP_CONFIG_PRIVATE_H
#define	HTP_CONFIG_PRIVATE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define HTP_DECODER_CONTEXTS_MAX    3

typedef struct htp_decoder_cfg_t {

    // Path-specific decoding options.

    /** Convert backslash characters to slashes. */
    int backslash_convert_slashes;
    
    /** Convert to lowercase. */
    int convert_lowercase;
    
    /** Compress slash characters. */
    int path_separators_compress;

    /** Should we URL-decode encoded path segment separators? */
    int path_separators_decode;

    /** Should we decode '+' characters to spaces? */
    int plusspace_decode;
    
    /** Reaction to encoded path separators. */
    enum htp_unwanted_t path_separators_encoded_unwanted;


    // Special characters options.

    /** Controls how raw NUL bytes are handled. */
    int nul_raw_terminates;

    /** Determines server response to a raw NUL byte in the path. */
    enum htp_unwanted_t nul_raw_unwanted;

    /** Reaction to control characters. */
    enum htp_unwanted_t control_chars_unwanted;


    // URL encoding options.

    /** Should we decode %u-encoded characters? */
    int u_encoding_decode;

    /** Reaction to %u encoding. */
    enum htp_unwanted_t u_encoding_unwanted;

    /** Handling of invalid URL encodings. */
    enum htp_url_encoding_handling_t url_encoding_invalid_handling;

    /** Reaction to invalid URL encoding. */
    enum htp_unwanted_t url_encoding_invalid_unwanted;
    
    /** Controls how encoded NUL bytes are handled. */
    int nul_encoded_terminates;

    /** How are we expected to react to an encoded NUL byte? */
    enum htp_unwanted_t nul_encoded_unwanted;


    // UTF-8 options.

    /** Controls how invalid UTF-8 characters are handled. */
    enum htp_unwanted_t utf8_invalid_unwanted;

    /** Convert UTF-8 characters into bytes using best-fit mapping. */
    int utf8_convert_bestfit;

    
    // Best-fit mapping options.

    /** The best-fit map to use to decode %u-encoded characters. */
    unsigned char *bestfit_map;

    /** The replacement byte used when there is no best-fit mapping. */
    unsigned char bestfit_replacement_byte;

} htp_decoder_cfg_t;

struct htp_cfg_t {
    /**
     * The maximum size of the buffer that is used when the current
     * input chunk does not contain all the necessary data (e.g., a very header
     * line that spans several packets).
     */
    size_t field_limit_hard;

    /**
     * Soft field limit length. If this limit is reached the parser will issue
     * a warning but continue to run. NOT IMPLEMENTED.
     */
    size_t field_limit_soft;

    /**
     * Log level, which will be used when deciding whether to store or
     * ignore the messages issued by the parser.
     */
    enum htp_log_level_t log_level;

    /**
     * Whether to delete each transaction after the last hook is invoked. This
     * feature should be used when parsing traffic streams in real time.
     */
    int tx_auto_destroy;

    /**
     * Server personality identifier.
     */
    enum htp_server_personality_t server_personality;

    /** The function used for request line parsing. Depends on the personality. */
    int (*parse_request_line)(htp_connp_t *connp);

    /** The function used for response line parsing. Depends on the personality. */
    int (*parse_response_line)(htp_connp_t *connp);

    /** The function used for request header parsing. Depends on the personality. */
    int (*process_request_header)(htp_connp_t *connp, unsigned char *data, size_t len);

    /** The function used for response header parsing. Depends on the personality. */
    int (*process_response_header)(htp_connp_t *connp, unsigned char *data, size_t len);

    /** The function to use to transform parameters after parsing. */
    int (*parameter_processor)(htp_param_t *param);

    /** Decoder configuration array, one per context. */
    htp_decoder_cfg_t decoder_cfgs[HTP_DECODER_CONTEXTS_MAX];

    /** Whether to generate the request_uri_normalized field. */
    int generate_request_uri_normalized;

    /** Whether to decompress compressed response bodies. */
    int response_decompression_enabled;

    /** Not fully implemented at the moment. */
    char *request_encoding;

    /** Not fully implemented at the moment. */
    char *internal_encoding;

    /** Whether to parse request cookies. */
    int parse_request_cookies;

    /** Whether to parse HTTP Authentication headers. */
    int parse_request_auth;

    /** Whether to extract files from requests using Multipart encoding. */
    int extract_request_files;

    /** How many extracted files are allowed in a single Multipart request? */
    int extract_request_files_limit;

    /** The location on disk where temporary files will be created. */
    char *tmpdir;

    // Hooks

    /**
     * Request start hook, invoked when the parser receives the first byte of a new
     * request. Because in HTTP a transaction always starts with a request, this hook
     * doubles as a transaction start hook.
     */
    htp_hook_t *hook_request_start;

    /**
     * Request line hook, invoked after a request line has been parsed.
     */
    htp_hook_t *hook_request_line;

    /**
     * Request URI normalization hook, for overriding default normalization of URI.
     */
    htp_hook_t *hook_request_uri_normalize;

    /**
     * Receives raw request header data, starting immediately after the request line,
     * including all headers as they are seen on the TCP connection, and including the
     * terminating empty line. Not available on genuine HTTP/0.9 requests (because
     * they don't use headers).
     */
    htp_hook_t *hook_request_header_data;

    /**
     * Request headers hook, invoked after all request headers are seen.
     */
    htp_hook_t *hook_request_headers;

    /**
     * Request body data hook, invoked every time body data is available. Each
     * invocation will provide a htp_tx_data_t instance. Chunked data
     * will be dechunked before the data is passed to this hook. Decompression
     * is not currently implemented. At the end of the request body
     * there will be a call with the data pointer set to NULL.
     */
    htp_hook_t *hook_request_body_data;

    /**
     * Request file data hook, which is invoked whenever request file data is
     * available. Currently used only by the Multipart parser.
     */
    htp_hook_t *hook_request_file_data;

    /**
     * Receives raw request trailer data, which can be available on requests that have
     * chunked bodies. The data starts immediately after the zero-length chunk
     * and includes the terminating empty line.
     */
    htp_hook_t *hook_request_trailer_data;

    /**
     * Request trailer hook, invoked after all trailer headers are seen,
     * and if they are seen (not invoked otherwise).
     */
    htp_hook_t *hook_request_trailer;

    /**
     * Request hook, invoked after a complete request is seen.
     */
    htp_hook_t *hook_request_complete;

    /**
     * Response startup hook, invoked when a response transaction is found and
     * processing started.
     */
    htp_hook_t *hook_response_start;

    /**
     * Response line hook, invoked after a response line has been parsed.
     */
    htp_hook_t *hook_response_line;

    /**
     * Receives raw response header data, starting immediately after the status line
     * and including all headers as they are seen on the TCP connection, and including the
     * terminating empty line. Not available on genuine HTTP/0.9 responses (because
     * they don't have response headers).
     */
    htp_hook_t *hook_response_header_data;

    /**
     * Response headers book, invoked after all response headers have been seen.
     */
    htp_hook_t *hook_response_headers;

    /**
     * Response body data hook, invoked every time body data is available. Each
     * invocation will provide a htp_tx_data_t instance. Chunked data
     * will be dechunked before the data is passed to this hook. By default,
     * compressed data will be decompressed, but decompression can be disabled
     * in configuration. At the end of the response body there will be a call
     * with the data pointer set to NULL.
     */
    htp_hook_t *hook_response_body_data;

    /**
     * Receives raw response trailer data, which can be available on responses that have
     * chunked bodies. The data starts immediately after the zero-length chunk
     * and includes the terminating empty line.
     */
    htp_hook_t *hook_response_trailer_data;

    /**
     * Response trailer hook, invoked after all trailer headers have been processed,
     * and only if the trailer exists.
     */
    htp_hook_t *hook_response_trailer;

    /**
     * Response hook, invoked after a response has been seen. Because sometimes servers
     * respond before receiving complete requests, a response_complete callback may be
     * invoked prior to a request_complete callback.
     */
    htp_hook_t *hook_response_complete;

    /**
     * Transaction complete hook, which is invoked once the entire transaction is
     * considered complete (request and response are both complete). This is always
     * the last hook to be invoked.
     */
    htp_hook_t *hook_transaction_complete;

    /**
     * Log hook, invoked every time the library wants to log.
     */
    htp_hook_t *hook_log;

    /**
     * Opaque user data associated with this configuration structure.
     */
    void *user_data;

    // Request Line parsing options.

    // TODO this was added here to maintain a stable ABI, once we can break that
    // we may want to move this into htp_decoder_cfg_t (VJ)

    /** Reaction to leading whitespace on the request line */
    enum htp_unwanted_t requestline_leading_whitespace_unwanted;

    /** How many layers of compression we will decompress (0 => no limit). */
    int response_decompression_layer_limit;
};

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_CONFIG_PRIVATE H */

