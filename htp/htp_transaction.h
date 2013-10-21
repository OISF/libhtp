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

/* 
 * @file
 * @author Ivan Ristic <ivanr@webkreator.com>
 */

#ifndef HTP_TRANSACTION_H
#define	HTP_TRANSACTION_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "htp.h"

/**
 * Enumerate possible data handling strategies in hybrid parsing
 * mode. The two possibilities are to make copies of all data and
 * use bstr instances to wrap already available data.
 */
enum htp_alloc_strategy_t {
    /**
     * Make copies of all data. This strategy should be used when
     * the supplied buffers are transient and will go away after
     * the invoked function returns.
     */
    HTP_ALLOC_COPY  = 1,

    /**
     * Reuse buffers, without a change of ownership. We assume the
     * buffers will continue to be available until the transaction
     * is deleted by the container.
     */
    HTP_ALLOC_REUSE = 2
};

/**
 * Possible states of a progressing transaction. Internally, progress will change
 * to the next state when the processing activities associated with that state
 * begin. For example, when we start to process request line bytes, the request
 * state will change from HTP_REQUEST_NOT_STARTED to HTP_REQUEST_LINE.*
 */
enum htp_tx_req_progress_t {
    HTP_REQUEST_NOT_STARTED = 0,
    HTP_REQUEST_LINE = 1,
    HTP_REQUEST_HEADERS = 2,
    HTP_REQUEST_BODY = 3,
    HTP_REQUEST_TRAILER = 4,
    HTP_REQUEST_COMPLETE = 5    
};

enum htp_tx_res_progress_t {
    HTP_RESPONSE_NOT_STARTED = 0,
    HTP_RESPONSE_LINE = 1,
    HTP_RESPONSE_HEADERS = 2,
    HTP_RESPONSE_BODY = 3,
    HTP_RESPONSE_TRAILER = 4,
    HTP_RESPONSE_COMPLETE = 5
};

#define HTP_CONFIG_PRIVATE      0
#define HTP_CONFIG_SHARED       1

/**
 * Creates a new transaction structure.
 *
 * @param[in] connp Connection parser pointer. Must not be NULL.
 * @return The newly created transaction, or NULL on memory allocation failure.
 */
htp_tx_t *htp_tx_create(htp_connp_t *connp);

/**
 * Destroys the supplied transaction.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 */
htp_status_t htp_tx_destroy(htp_tx_t *tx);

/**
 * Determines if the transaction used a shared configuration structure. See the
 * documentation for htp_tx_set_config() for more information why you might want
 * to know that.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_CFG_SHARED or HTP_CFG_PRIVATE.
 */
int htp_tx_get_is_config_shared(const htp_tx_t *tx);

/**
 * Returns the user data associated with this transaction.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return A pointer to user data or NULL.
 */
void *htp_tx_get_user_data(const htp_tx_t *tx);

/**
 * Registers a callback that will be invoked to process the transaction's request body data.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] callback_fn Callback function pointer. Must not be NULL.
 */
void htp_tx_register_request_body_data(htp_tx_t *tx, int (*callback_fn)(htp_tx_data_t *));

/**
 * Registers a callback that will be invoked to process the transaction's response body data.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] callback_fn Callback function pointer. Must not be NULL.
 */
void htp_tx_register_response_body_data(htp_tx_t *tx, int (*callback_fn)(htp_tx_data_t *));

/**
 * Adds one parameter to the request. THis function will take over the
 * responsibility for the provided htp_param_t structure.
 * 
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] param Parameter pointer. Must not be NULL.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_req_add_param(htp_tx_t *tx, htp_param_t *param);

/**
 * Returns the first request parameter that matches the given name, using case-insensitive matching.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] name Name data pointer. Must not be NULL.
 * @param[in] name_len Name data length.
 * @return htp_param_t instance, or NULL if parameter not found.
 */
htp_param_t *htp_tx_req_get_param(htp_tx_t *tx, const char *name, size_t name_len);

/**
 * Returns the first request parameter from the given source that matches the given name,
 * using case-insensitive matching.
 * 
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] source Parameter source (where in request the parameter was located).
 * @param[in] name Name data pointer. Must not be NULL.
 * @param[in] name_len Name data length.
 * @return htp_param_t instance, or NULL if parameter not found.
 */
htp_param_t *htp_tx_req_get_param_ex(htp_tx_t *tx, enum htp_data_source_t source, const char *name, size_t name_len);

/**
 * Determine if the request has a body.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return 1 if there is a body, 0 otherwise.
 */
int htp_tx_req_has_body(const htp_tx_t *tx);

/**
 * Process a chunk of request body data. This function assumes that
 * handling of chunked encoding is implemented by the container. When
 * you're done submitting body data, invoke a state change (to REQUEST)
 * to finalize any processing that might be pending. The supplied data is
 * fully consumed and there is no expectation that it will be available
 * afterwards. The protocol parsing code makes no copies of the data,
 * but some parsers might.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] data Data pointer. Must not be NULL.
 * @param[in] len Data length.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_req_process_body_data(htp_tx_t *tx, const void *data, size_t len);

/**
 * Set one request header. This function should be invoked once for
 * each available header, and in the order in which headers were
 * seen in the request.
 * 
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] name Name data pointer. Must not be NULL.
 * @param[in] name_len Name data length.
 * @param[in] value Value data pointer. Must not be NULL.
 * @param[in] value_len Value data length.
 * @param[in] alloc Desired allocation strategy.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_req_set_header(htp_tx_t *tx, const char *name, size_t name_len,
        const char *value, size_t value_len, enum htp_alloc_strategy_t alloc);

/**
 * Removes all request headers associated with this transaction. This
 * function is needed because in some cases the container does not
 * differentiate between standard and trailing headers. In that case,
 * you set request headers once at the beginning of the transaction,
 * read the body (at this point the request headers should contain the
 * mix of regular and trailing headers), clear all headers, and then set
 * them all again.
 * 
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_req_set_headers_clear(htp_tx_t *tx);

/**
 * Set request line. When used, this function should always be called first,
 * with more specific functions following. Must not contain line terminators.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] line Line data pointer. Must not be NULL.
 * @param[in] line_len Line data length.
 * @param[in] alloc Desired allocation strategy.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_req_set_line(htp_tx_t *tx, const char *line, size_t line_len, enum htp_alloc_strategy_t alloc);

/**
 * Set transaction request method. This function will enable you to keep
 * track of the text representation of the method.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] method Method data pointer. Must not be NULL.
 * @param[in] method_len Method data length.
 * @param[in] alloc Desired allocation strategy.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_req_set_method(htp_tx_t *tx, const char *method, size_t method_len, enum htp_alloc_strategy_t alloc);

/**
 * Set transaction request method number. This function enables you to
 * keep track how a particular method string is interpreted. This function
 * is useful with web servers that ignore invalid methods; for example, some
 * web servers will treat them as a GET.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] method_number Method number.
 */
void htp_tx_req_set_method_number(htp_tx_t *tx, enum htp_method_t method_number);

/**
 * Set parsed request URI. You don't need to use this function if you are already providing
 * the request line or request URI. But if your container already has this data available,
 * feeding it to LibHTP will minimize any potential data differences. This function assumes
 * management of the data provided in parsed_uri. This function will not change htp_tx_t::parsed_uri_raw
 * (which may have data in it from the parsing of the request URI).
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] parsed_uri URI pointer. Must not be NULL.
 */
void htp_tx_req_set_parsed_uri(htp_tx_t *tx, htp_uri_t *parsed_uri);

/**
 * Forces HTTP/0.9 as the transaction protocol. This method exists to ensure
 * that both LibHTP and the container treat the transaction as HTTP/0.9, despite
 * potential differences in how the protocol version is determined.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] is_protocol_0_9 Zero if protocol is not HTTP/0.9, or 1 if it is.
 */
void htp_tx_req_set_protocol_0_9(htp_tx_t *tx, int is_protocol_0_9);

/**
 * Sets the request protocol string (e.g., "HTTP/1.0"). The information provided
 * is only stored, not parsed. Use htp_tx_req_set_protocol_number() to set the
 * actual protocol number, as interpreted by the container.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] protocol Protocol data pointer. Must not be NULL.
 * @param[in] protocol_len Protocol data length.
 * @param[in] alloc Desired allocation strategy.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_req_set_protocol(htp_tx_t *tx, const char *protocol, size_t protocol_len, enum htp_alloc_strategy_t alloc);

/**
 * Set request protocol version number. Must be invoked after
 * htp_txh_set_req_protocol(), because it will overwrite the previously
 * extracted version number. Convert the protocol version number to an integer
 * by multiplying it with 100. For example, 1.1 becomes 110. Alternatively,
 * use the HTP_PROTOCOL_0_9, HTP_PROTOCOL_1_0, and HTP_PROTOCOL_1_1 constants.
 * Note: setting protocol to HTP_PROTOCOL_0_9 alone will _not_ get the library to
 * treat the transaction as HTTP/0.9. You need to also invoke htp_tx_req_set_protocol_0_9().
 * This is because HTTP 0.9 is used only when protocol information is absent from the
 * request line, and not when it is explicitly stated (as "HTTP/0.9"). This behavior is
 * consistent with that of Apache httpd.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] protocol_number Protocol number.
 */
void htp_tx_req_set_protocol_number(htp_tx_t *tx, int protocol_number);

/**
 * Set transaction request URI. The value provided here will be stored in htp_tx_t::request_uri
 * and subsequently parsed. If htp_tx_req_set_line() was previously used, the uri provided
 * when calling this function will overwrite any previously parsed value.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] uri URI data pointer. Must not be NULL.
 * @param[in] uri_len URI data length.
 * @param[in] alloc Desired allocation strategy.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_req_set_uri(htp_tx_t *tx, const char *uri, size_t uri_len, enum htp_alloc_strategy_t alloc);

/**
 * Process a chunk of response body data. This function assumes that
 * handling of chunked encoding is implemented by the container. When
 * you're done submitting body data, invoking a state change (to RESPONSE)
 * will finalize any processing that might be pending.
 *
 * The response body data will be decompressed if two conditions are met: one,
 * decompression is enabled in configuration and two, if the response headers
 * indicate compression. Alternatively, you can control decompression from
 * a RESPONSE_HEADERS callback, by setting tx->response_content_encoding either
 * to COMPRESSION_NONE (to disable compression), or to one of the supported
 * decompression algorithms.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] data Data pointer. Must not be NULL.
 * @param[in] len Data length.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_res_process_body_data(htp_tx_t *tx, const void *data, size_t len);

/**
 * Set one response header. This function should be invoked once for
 * each available header, and in the order in which headers were
 * seen in the response.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] name Name data pointer. Must not be NULL.
 * @param[in] name_len Name data length.
 * @param[in] value Value data pointer. Must not be NULL.
 * @param[in] value_len Value length.
 * @param[in] alloc Desired allocation strategy.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_res_set_header(htp_tx_t *tx, const char *name, size_t name_len,
        const char *value, size_t value_len, enum htp_alloc_strategy_t alloc);

/**
 * Removes all response headers associated with this transaction. This
 * function is needed because in some cases the container does not
 * differentiate between standard and trailing headers. In that case,
 * you set response headers once at the beginning of the transaction,
 * read the body, clear all headers, and then set them all again. After
 * the headers are set for the second time, they will potentially contain
 * a mixture of standard and trailing headers.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_res_set_headers_clear(htp_tx_t *tx);

/**
 * Set response protocol number. See htp_tx_res_set_protocol_number() for more information
 * about the correct format of the protocol_parameter parameter.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] protocol_number Protocol number.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
void htp_tx_res_set_protocol_number(htp_tx_t *tx, int protocol_number);

/**
 * Set response line. Use this function is you have a single buffer containing
 * the entire line. If you have individual request line pieces, use the other
 * available functions.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] line Line data pointer. Must not be NULL.
 * @param[in] line_len Line data length.
 * @param[in] alloc Desired allocation strategy.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_res_set_status_line(htp_tx_t *tx, const char *line, size_t line_len, enum htp_alloc_strategy_t alloc);

/**
 * Set response status code.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] status_code Response status code.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
void htp_tx_res_set_status_code(htp_tx_t *tx, int status_code);

/**
 * Set response status message, which is the part of the response
 * line that comes after the status code.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] msg Message data pointer. Must not be NULL.
 * @param[in] msg_len Message data length.
 * @param[in] alloc Desired allocation strategy.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_tx_res_set_status_message(htp_tx_t *tx, const char *msg, size_t msg_len, enum htp_alloc_strategy_t alloc);

/**
 * Sets the configuration that is to be used for this transaction. If the
 * second parameter is set to HTP_CFG_PRIVATE, the transaction will adopt
 * the configuration structure and destroy it when appropriate. This function is
 * useful if you need to make changes to configuration on per-transaction basis.
 * Initially, all transactions will share the configuration with that of the
 * connection; if you were to make changes on it, they would affect all
 * current and future connections. To work around that, you make a copy of the
 * configuration object, call this function with the second parameter set to
 * HTP_CFG_PRIVATE, and modify configuration at will.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] cfg Configuration pointer. Must not be NULL.
 * @param[in] is_cfg_shared HTP_CFG_SHARED or HTP_CFG_PRIVATE
 */
void htp_tx_set_config(htp_tx_t *tx, htp_cfg_t *cfg, int is_cfg_shared);

/**
 * Associates user data with this transaction.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @param[in] user_data Opaque user data pointer.
 */
void htp_tx_set_user_data(htp_tx_t *tx, void *user_data);

/**
 * Change transaction state to REQUEST and invoke registered callbacks.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success; HTP_ERROR on error, HTP_STOP if one of the
 *         callbacks does not want to follow the transaction any more.
 */
htp_status_t htp_tx_state_request_complete(htp_tx_t *tx);

/**
 * Change transaction state to REQUEST_HEADERS and invoke all
 * registered callbacks.
 * 
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success; HTP_ERROR on error, HTP_STOP if one of the
 *         callbacks does not want to follow the transaction any more.
 */
htp_status_t htp_tx_state_request_headers(htp_tx_t *tx);

/**
 * Change transaction state to REQUEST_LINE and invoke all
 * registered callbacks.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success; HTP_ERROR on error, HTP_STOP if one of the
 *         callbacks does not want to follow the transaction any more.
 */
htp_status_t htp_tx_state_request_line(htp_tx_t *tx);
    
/**
 * Initialize hybrid parsing mode, change state to TRANSACTION_START,
 * and invoke all registered callbacks.
 * 
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success; HTP_ERROR on error, HTP_STOP if one of the
 *         callbacks does not want to follow the transaction any more.
 */
htp_status_t htp_tx_state_request_start(htp_tx_t *tx);

/**
 * Change transaction state to RESPONSE and invoke registered callbacks.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success; HTP_ERROR on error, HTP_STOP if one of the
 *         callbacks does not want to follow the transaction any more.
 */
htp_status_t htp_tx_state_response_complete(htp_tx_t *tx);

/**
 * Change transaction state to RESPONSE_HEADERS and invoke registered callbacks.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success; HTP_ERROR on error, HTP_STOP if one of the
 *         callbacks does not want to follow the transaction any more.
 */
htp_status_t htp_tx_state_response_headers(htp_tx_t *tx);

/**
 * Change transaction state to HTP_RESPONSE_LINE and invoke registered callbacks.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success; HTP_ERROR on error, HTP_STOP if one of the
 *         callbacks does not want to follow the transaction any more.
 */
htp_status_t htp_tx_state_response_line(htp_tx_t *tx);

/**
 * Change transaction state to RESPONSE_START and invoke registered callbacks.
 *
 * @param[in] tx Transaction pointer. Must not be NULL.
 * @return HTP_OK on success; HTP_ERROR on error, HTP_STOP if one of the
 *         callbacks does not want to follow the transaction any more.
 */
htp_status_t htp_tx_state_response_start(htp_tx_t *tx);    

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_HYBRID_H */
