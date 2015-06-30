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

#ifndef HTP_CONFIG_H
#define	HTP_CONFIG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "htp.h"

/**
 * Decoder contexts.
 */
enum htp_decoder_ctx_t {
    /** Default settings. Settings applied to this context are propagated to all other contexts. */
    HTP_DECODER_DEFAULTS = 0,

    /** Urlencoded decoder settings. */
    HTP_DECODER_URLENCODED = 1,

    /** URL path decoder settings. */
    HTP_DECODER_URL_PATH = 2    
};

/**
 * Enumerates the possible server personalities.
 */
enum htp_server_personality_t {
    /**
     * Minimal personality that performs at little work as possible. All optional
     * features are disabled. This personality is a good starting point for customization.
     */
    HTP_SERVER_MINIMAL = 0,

    /** A generic personality that aims to work reasonably well for all server types. */
    HTP_SERVER_GENERIC = 1,

    /** The IDS personality tries to perform as much decoding as possible. */
    HTP_SERVER_IDS = 2,

    /** Mimics the behavior of IIS 4.0, as shipped with Windows NT 4.0. */
    HTP_SERVER_IIS_4_0 = 3,

    /** Mimics the behavior of IIS 5.0, as shipped with Windows 2000. */
    HTP_SERVER_IIS_5_0 = 4,

    /** Mimics the behavior of IIS 5.1, as shipped with Windows XP Professional. */
    HTP_SERVER_IIS_5_1 = 5,

    /** Mimics the behavior of IIS 6.0, as shipped with Windows 2003. */
    HTP_SERVER_IIS_6_0 = 6,

    /** Mimics the behavior of IIS 7.0, as shipped with Windows 2008. */
    HTP_SERVER_IIS_7_0 = 7,

    /* Mimics the behavior of IIS 7.5, as shipped with Windows 7. */
    HTP_SERVER_IIS_7_5 = 8,

    /* Mimics the behavior of Apache 2.x. */
    HTP_SERVER_APACHE_2 = 9
};

/**
 * Enumerates the ways in which servers respond to malformed data.
 */
enum htp_unwanted_t {

    /** Ignores problem. */
    HTP_UNWANTED_IGNORE = 0,

    /** Responds with HTTP 400 status code. */
    HTP_UNWANTED_400 = 400,

    /** Responds with HTTP 404 status code. */
    HTP_UNWANTED_404 = 404
};

/**
 * Enumerates the possible approaches to handling invalid URL-encodings.
 */
enum htp_url_encoding_handling_t {
    /** Ignore invalid URL encodings and leave the % in the data. */
    HTP_URL_DECODE_PRESERVE_PERCENT = 0,

    /** Ignore invalid URL encodings, but remove the % from the data. */
    HTP_URL_DECODE_REMOVE_PERCENT = 1,

    /** Decode invalid URL encodings. */
    HTP_URL_DECODE_PROCESS_INVALID = 2
};

/**
 * Creates a new configuration structure. Configuration structures created at
 * configuration time must not be changed afterwards in order to support lock-less
 * copying.
 *
 * @return New configuration structure.
 */
htp_cfg_t *htp_config_create(void);

/**
 * Creates a copy of the supplied configuration structure. The idea is to create
 * one or more configuration objects at configuration-time, but to use this
 * function to create per-connection copies. That way it will be possible to
 * adjust per-connection configuration as necessary, without affecting the
 * global configuration. Make sure no other thread changes the configuration
 * object while this function is operating.
 *
 * @param[in] cfg
 * @return A copy of the configuration structure.
 */
htp_cfg_t *htp_config_copy(htp_cfg_t *cfg);

/**
 * Destroy a configuration structure.
 *
 * @param[in] cfg
 */
void htp_config_destroy(htp_cfg_t *cfg);

/**
 * Retrieves user data associated with this configuration.
 *
 * @param[in] cfg
 * @return User data pointer, or NULL if not set.
 */
void *htp_config_get_user_data(htp_cfg_t *cfg);

/**
 * Registers a callback that is invoked every time there is a log message with
 * severity equal and higher than the configured log level.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_log(htp_cfg_t *cfg, int (*callback_fn)(htp_log_t *));

/**
 * Adds the built-in Multipart parser to the configuration. This parser will extract information
 * stored in request bodies, when they are in multipart/form-data format.
 *
 * @param[in] cfg
 */
void htp_config_register_multipart_parser(htp_cfg_t *cfg);

/**
 * Registers a REQUEST_START callback, which is invoked every time a new
 * request begins and before any parsing is done.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_start(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a REQUEST_BODY_DATA callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *));

/**
 * Registers a REQUEST_COMPLETE callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a REQUEST_FILE_DATA callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_file_data(htp_cfg_t *cfg, int (*callback_fn)(htp_file_data_t *));

/**
 * Registers a REQUEST_HEADER_DATA callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_header_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *));

/**
 * Registers a REQUEST_HEADERS callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a REQUEST_LINE callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_line(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a REQUEST_URI_NORMALIZE callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_uri_normalize(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a HTP_REQUEST_TRAILER callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a REQUEST_TRAILER_DATA callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_request_trailer_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *d));

/**
 * Registers a RESPONSE_BODY_DATA callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_response_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *));

/**
 * Registers a RESPONSE_COMPLETE callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_response_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a RESPONSE_HEADER_DATA callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_response_header_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *));

/**
 * Registers a RESPONSE_HEADERS callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_response_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a RESPONSE_LINE callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_response_line(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a RESPONSE_START callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_response_start(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a RESPONSE_TRAILER callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_response_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Registers a RESPONSE_TRAILER_DATA callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_response_trailer_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *d));

/**
 * Registers a TRANSACTION_COMPLETE callback.
 *
 * @param[in] cfg
 * @param[in] callback_fn
 */
void htp_config_register_transaction_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *));

/**
 * Adds the built-in Urlencoded parser to the configuration. The parser will
 * parse query strings and request bodies with the appropriate MIME type.
 *
 * @param[in] cfg
 */
void htp_config_register_urlencoded_parser(htp_cfg_t *cfg);

/**
 * Configures whether backslash characters are treated as path segment separators. They
 * are not on Unix systems, but are on Windows systems. If this setting is enabled, a path
 * such as "/one\two/three" will be converted to "/one/two/three". Implemented only for HTP_DECODER_URL_PATH.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_backslash_convert_slashes(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Configures a best-fit map, which is used whenever characters longer than one byte
 * need to be converted to a single-byte. By default a Windows 1252 best-fit map is used.
 * The map is an list of triplets, the first 2 bytes being an UCS-2 character to map from,
 * and the third byte being the single byte to map to. Make sure that your map contains
 * the mappings to cover the full-width and half-width form characters (U+FF00-FFEF). The
 * last triplet in the map must be all zeros (3 NUL bytes).
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] map
 */
void htp_config_set_bestfit_map(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, void *map);

/**
 * Sets the replacement character that will be used to in the lossy best-fit
 * mapping from multi-byte to single-byte streams. The question mark character
 * is used as the default replacement byte.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] replacement_byte
 */
void htp_config_set_bestfit_replacement_byte(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int replacement_byte);

/**
 * Controls reaction to raw control characters in the data.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] unwanted
 */
void htp_config_set_control_chars_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted);

/**
 * Configures whether input data will be converted to lowercase. Useful when set on the
 * HTP_DECODER_URL_PATH context, in order to handle servers with case-insensitive filesystems.
 * Implemented only for HTP_DECODER_URL_PATH.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_convert_lowercase(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Enables or disables Multipart file extraction. This function can be invoked only
 * after a previous htp_config_set_tmpdir() invocation. Otherwise, the configuration
 * change will fail, and extraction will not be enabled. Disabled by default. Please
 * note that the built-in file extraction implementation uses synchronous I/O, which
 * means that it is not suitable for use in an event-driven container. There's an
 * upper limit to how many files can be created on the filesystem during a single
 * request. The limit exists in order to mitigate against a DoS attack with a
 * Multipart payload that contains hundreds and thousands of files (it's cheap for the
 * attacker to do this, but costly for the server to support it). The default limit
 * may be pretty conservative.
 *
 * @param[in] cfg
 * @param[in] extract_files 1 if you wish extraction to be enabled, 0 otherwise
 * @param[in] limit the maximum number of files allowed; use -1 to use the parser default.
 */
htp_status_t htp_config_set_extract_request_files(htp_cfg_t *cfg, int extract_files, int limit);

/**
 * Configures the maximum size of the buffer LibHTP will use when all data is not available
 * in the current buffer (e.g., a very long header line that might span several packets). This
 * limit is controlled by the hard_limit parameter. The soft_limit parameter is not implemented.
 * 
 * @param[in] cfg
 * @param[in] soft_limit NOT IMPLEMENTED.
 * @param[in] hard_limit
 */
void htp_config_set_field_limits(htp_cfg_t *cfg, size_t soft_limit, size_t hard_limit);

/**
 * Configures the desired log level.
 * 
 * @param[in] cfg
 * @param[in] log_level
 */
void htp_config_set_log_level(htp_cfg_t *cfg, enum htp_log_level_t log_level);

/**
 * Configures how the server reacts to encoded NUL bytes. Some servers will stop at
 * at NUL, while some will respond with 400 or 404. When the termination option is not
 * used, the NUL byte will remain in the path.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_nul_encoded_terminates(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Configures reaction to encoded NUL bytes in input data.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] unwanted
 */
void htp_config_set_nul_encoded_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted);

/**
 * Configures the handling of raw NUL bytes. If enabled, raw NUL terminates strings.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_nul_raw_terminates(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Configures how the server reacts to raw NUL bytes. Some servers will terminate
 * path at NUL, while some will respond with 400 or 404. When the termination option
 * is not used, the NUL byte will remain in the data.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] unwanted
 */
void htp_config_set_nul_raw_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted);

/**
 * Enable or disable request HTTP Authentication parsing. Enabled by default.
 *
 * @param[in] cfg
 * @param[in] parse_request_auth
 */
void htp_config_set_parse_request_auth(htp_cfg_t *cfg, int parse_request_auth);

/**
 * Enable or disable request cookie parsing. Enabled by default.
 *
 * @param[in] cfg
 * @param[in] parse_request_cookies
 */
void htp_config_set_parse_request_cookies(htp_cfg_t *cfg, int parse_request_cookies);

/**
 * Configures whether consecutive path segment separators will be compressed. When enabled, a path
 * such as "/one//two" will be normalized to "/one/two". Backslash conversion and path segment separator
 * decoding are carried out before compression. For example, the path "/one\\/two\/%5cthree/%2f//four"
 * will be converted to "/one/two/three/four" (assuming all 3 options are enabled). Implemented only for
 * HTP_DECODER_URL_PATH.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_path_separators_compress(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Configures whether encoded path segment separators will be decoded. Apache does not do
 * this by default, but IIS does. If enabled, a path such as "/one%2ftwo" will be normalized
 * to "/one/two". If the backslash_separators option is also enabled, encoded backslash
 * characters will be converted too (and subsequently normalized to forward slashes). Implemented
 * only for HTP_DECODER_URL_PATH.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_path_separators_decode(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Configures reaction to encoded path separator characters (e.g., %2f). Implemented only for HTP_DECODER_URL_PATH.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] unwanted
 */
void htp_config_set_path_separators_encoded_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted);

/**
 * Configures whether plus characters are converted to spaces when decoding URL-encoded strings. This
 * is appropriate to do for parameters, but not for URLs. Only applies to contexts where decoding
 * is taking place.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_plusspace_decode(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Controls whether compressed response bodies will be automatically decompressed.
 *
 * @param[in] cfg
 * @param[in] enabled set to 1 to enable decompression, 0 otherwise
 */
void htp_config_set_response_decompression(htp_cfg_t *cfg, int enabled);

/**
 * Configure desired server personality.
 *
 * @param[in] cfg
 * @param[in] personality
 * @return HTP_OK if the personality is supported, HTP_ERROR if it isn't.
 */
htp_status_t htp_config_set_server_personality(htp_cfg_t *cfg, enum htp_server_personality_t personality);

/**
 * Configures the path where temporary files should be stored. Must be set
 * in order to use the Multipart file extraction functionality.
 * 
 * @param[in] cfg
 * @param[in] tmpdir
 */
void htp_config_set_tmpdir(htp_cfg_t *cfg, char *tmpdir);

/**
 * Configures whether transactions will be automatically destroyed once they
 * are processed and all callbacks invoked. This option is appropriate for
 * programs that process transactions as they are processed.
 *
 * @param[in] cfg
 * @param[in] tx_auto_destroy
 */
void htp_config_set_tx_auto_destroy(htp_cfg_t *cfg, int tx_auto_destroy);

/**
 * Associates provided opaque user data with the configuration.
 * 
 * @param[in] cfg
 * @param[in] user_data
 */
void htp_config_set_user_data(htp_cfg_t *cfg, void *user_data);

/**
 * Configures whether %u-encoded sequences are decoded. Such sequences
 * will be treated as invalid URL encoding if decoding is not desirable.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_u_encoding_decode(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Configures reaction to %u-encoded sequences in input data.
 * 
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] unwanted
 */
void htp_config_set_u_encoding_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted);

/**
 * Configures how the server handles to invalid URL encoding.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] handling
 */
void htp_config_set_url_encoding_invalid_handling(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_url_encoding_handling_t handling);

/**
 * Configures how the server reacts to invalid URL encoding.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] unwanted
 */
void htp_config_set_url_encoding_invalid_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted);

/**
 * Controls whether the data should be treated as UTF-8 and converted to a single-byte
 * stream using best-fit mapping. Implemented only for HTP_DECODER_URL_PATH.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] enabled
 */
void htp_config_set_utf8_convert_bestfit(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled);

/**
 * Configures how the server reacts to invalid UTF-8 characters. This setting does
 * not affect path normalization; it only controls what response status will be expect for
 * a request that contains invalid UTF-8 characters. Implemented only for HTP_DECODER_URL_PATH.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] unwanted
 */
void htp_config_set_utf8_invalid_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted);

/**
 * Configures how the server reacts to leading whitespace on the request line.
 *
 * @param[in] cfg
 * @param[in] ctx
 * @param[in] unwanted
 */
void htp_config_set_requestline_leading_whitespace_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted);

/**
 * Configures many layers of compression we try to decompress.
 *
 * @param[in] cfg
 * @param[in] limit 0 disables limit
 */
void htp_config_set_response_decompression_layer_limit(htp_cfg_t *cfg, int limit);

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_CONFIG_H */

