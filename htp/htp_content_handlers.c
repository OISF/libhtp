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

#include "htp_config_auto.h"

#include "htp_private.h"

/**
 * This callback function feeds request body data to a Urlencoded parser
 * and, later, feeds the parsed parameters to the correct structures.
 *
 * @param[in] d
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_ch_urlencoded_callback_request_body_data(htp_tx_data_t *d) {
    htp_tx_t *tx = d->tx;

    // Check that we were not invoked again after the finalization.
    if (tx->request_urlenp_body->params == NULL) return HTP_ERROR;

    if (d->data != NULL) {
        // Process one chunk of data.
        htp_urlenp_parse_partial(tx->request_urlenp_body, d->data, d->len);
    } else {
        // Finalize parsing.
        htp_urlenp_finalize(tx->request_urlenp_body);

        // Add all parameters to the transaction.
        bstr *name = NULL;
        bstr *value = NULL;

        for (size_t i = 0, n = htp_table_size(tx->request_urlenp_body->params); i < n; i++) {
            value = htp_table_get_index(tx->request_urlenp_body->params, i, &name);

            htp_param_t *param = calloc(1, sizeof (htp_param_t));
            if (param == NULL) return HTP_ERROR;

            param->name = name;
            param->value = value;
            param->source = HTP_SOURCE_BODY;
            param->parser_id = HTP_PARSER_URLENCODED;
            param->parser_data = NULL;

            if (htp_tx_req_add_param(tx, param) != HTP_OK) {
                free(param);
                return HTP_ERROR;
            }
        }

        // All the parameter data is now owned by the transaction, and
        // the parser table used to store it is no longer needed. The
        // line below will destroy just the table, leaving keys intact.
        htp_table_destroy_ex(tx->request_urlenp_body->params);
        tx->request_urlenp_body->params = NULL;
    }

    return HTP_OK;
}

/**
 * Determine if the request has a Urlencoded body, and, if it does, create and
 * attach an instance of the Urlencoded parser to the transaction.
 *
 * @param[in] connp
 * @return HTP_OK if a new parser has been setup, HTP_DECLINED if the MIME type
 *         is not appropriate for this parser, and HTP_ERROR on failure.
 */
htp_status_t htp_ch_urlencoded_callback_request_headers(htp_tx_t *tx) {
    // Check the request content type to see if it matches our MIME type.
    if ((tx->request_content_type == NULL) || (!bstr_begins_with_c(tx->request_content_type, HTP_URLENCODED_MIME_TYPE))) {
        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_ch_urlencoded_callback_request_headers: Body not URLENCODED\n");
        #endif

        return HTP_DECLINED;
    }

    #ifdef HTP_DEBUG
    fprintf(stderr, "htp_ch_urlencoded_callback_request_headers: Parsing URLENCODED body\n");
    #endif

    // Create parser instance.
    tx->request_urlenp_body = htp_urlenp_create(tx);
    if (tx->request_urlenp_body == NULL) return HTP_ERROR;

    // Register a request body data callback.
    htp_tx_register_request_body_data(tx, htp_ch_urlencoded_callback_request_body_data);

    return HTP_OK;
}

/**
 * Parses request query string, if present.
 *
 * @param[in] connp
 * @param[in] raw_data
 * @param[in] raw_len
 * @return HTP_OK if query string was parsed, HTP_DECLINED if there was no query
 *         string, and HTP_ERROR on failure.
 */
htp_status_t htp_ch_urlencoded_callback_request_line(htp_tx_t *tx) {
    // Proceed only if there's something for us to parse.
    if ((tx->parsed_uri->query == NULL) || (bstr_len(tx->parsed_uri->query) == 0)) {
        return HTP_DECLINED;
    }

    // We have a non-zero length query string.

    tx->request_urlenp_query = htp_urlenp_create(tx);
    if (tx->request_urlenp_query == NULL) return HTP_ERROR;

    if (htp_urlenp_parse_complete(tx->request_urlenp_query, bstr_ptr(tx->parsed_uri->query),
            bstr_len(tx->parsed_uri->query)) != HTP_OK) {
        htp_urlenp_destroy(tx->request_urlenp_query);
        return HTP_ERROR;
    }

    // Add all parameters to the transaction.

    bstr *name = NULL;
    bstr *value = NULL;
    for (size_t i = 0, n = htp_table_size(tx->request_urlenp_query->params); i < n; i++) {
        value = htp_table_get_index(tx->request_urlenp_query->params, i, &name);

        htp_param_t *param = calloc(1, sizeof (htp_param_t));
        if (param == NULL) return HTP_ERROR;
        
        param->name = name;
        param->value = value;
        param->source = HTP_SOURCE_QUERY_STRING;
        param->parser_id = HTP_PARSER_URLENCODED;
        param->parser_data = NULL;

        if (htp_tx_req_add_param(tx, param) != HTP_OK) {
            free(param);
            return HTP_ERROR;
        }
    }

    // All the parameter data is now owned by the transaction, and
    // the parser table used to store it is no longer needed. The
    // line below will destroy just the table, leaving keys intact.
    htp_table_destroy_ex(tx->request_urlenp_query->params);
    tx->request_urlenp_query->params = NULL;

    htp_urlenp_destroy(tx->request_urlenp_query);
    tx->request_urlenp_query = NULL;

    return HTP_OK;
}

/**
 * Finalize Multipart processing.
 * 
 * @param[in] d
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_ch_multipart_callback_request_body_data(htp_tx_data_t *d) {
    htp_tx_t *tx = d->tx;

    // Check that we were not invoked again after the finalization.
    if (tx->request_mpartp->gave_up_data == 1) return HTP_ERROR;

    if (d->data != NULL) {
        // Process one chunk of data.
        htp_mpartp_parse(tx->request_mpartp, d->data, d->len);
    } else {
        // Finalize parsing.
        htp_mpartp_finalize(tx->request_mpartp);

        htp_multipart_t *body = htp_mpartp_get_multipart(tx->request_mpartp);

        for (size_t i = 0, n = htp_list_size(body->parts); i < n; i++) {
            htp_multipart_part_t *part = htp_list_get(body->parts, i);

            // Use text parameters.
            if (part->type == MULTIPART_PART_TEXT) {
                htp_param_t *param = calloc(1, sizeof (htp_param_t));
                if (param == NULL) return HTP_ERROR;
                param->name = part->name;
                param->value = part->value;
                param->source = HTP_SOURCE_BODY;
                param->parser_id = HTP_PARSER_MULTIPART;
                param->parser_data = part;

                if (htp_tx_req_add_param(tx, param) != HTP_OK) {
                    free(param);
                    return HTP_ERROR;
                }
            }
        }

        // Tell the parser that it no longer owns names
        // and values of MULTIPART_PART_TEXT parts.
        tx->request_mpartp->gave_up_data = 1;
    }

    return HTP_OK;
}

/**
 * Inspect request headers and register the Multipart request data hook
 * if it contains a multipart/form-data body.
 *
 * @param[in] connp
 * @return HTP_OK if a new parser has been setup, HTP_DECLINED if the MIME type
 *         is not appropriate for this parser, and HTP_ERROR on failure.
 */
htp_status_t htp_ch_multipart_callback_request_headers(htp_tx_t *tx) {
    #ifdef HTP_DEBUG
    fprintf(stderr, "htp_ch_multipart_callback_request_headers: Need to determine if multipart body is present\n");
    #endif

    // The field tx->request_content_type does not contain the entire C-T
    // value and so we cannot use it to look for a boundary, but we can
    // use it for a quick check to determine if the C-T header exists.
    if (tx->request_content_type == NULL) {
        #ifdef HTP_DEBUG
        fprintf(stderr, "htp_ch_multipart_callback_request_headers: Not multipart body (no C-T header)\n");
        #endif

        return HTP_DECLINED;
    }

    // Look for a boundary. 

    htp_header_t *ct = htp_table_get_c(tx->request_headers, "content-type");
    if (ct == NULL) return HTP_ERROR;

    bstr *boundary = NULL;
    uint64_t flags = 0;

    htp_status_t rc = htp_mpartp_find_boundary(ct->value, &boundary, &flags);
    if (rc != HTP_OK) {
        #ifdef HTP_DEBUG
        if (rc == HTP_DECLINED) {
            fprintf(stderr, "htp_ch_multipart_callback_request_headers: Not multipart body\n");
        }
        #endif

        // No boundary (HTP_DECLINED) or error (HTP_ERROR).
        return rc;
    }

    if (boundary == NULL) return HTP_ERROR;

    // Create a Multipart parser instance.
    tx->request_mpartp = htp_mpartp_create(tx->connp->cfg, boundary, flags);
    if (tx->request_mpartp == NULL) {
        bstr_free(boundary);
        return HTP_ERROR;
    }

    // Configure file extraction.
    if (tx->cfg->extract_request_files) {
        tx->request_mpartp->extract_files = 1;
        tx->request_mpartp->extract_dir = tx->connp->cfg->tmpdir;
    }

    // Register a request body data callback.
    htp_tx_register_request_body_data(tx, htp_ch_multipart_callback_request_body_data);

    return HTP_OK;
}
