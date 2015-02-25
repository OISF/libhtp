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
 * This method is invoked whenever a piece of data, belonging to a single field (name or value)
 * becomes available. It will either create a new parameter or store the transient information
 * until a parameter can be created.
 *
 * @param[in] urlenp
 * @param[in] data
 * @param[in] startpos
 * @param[in] endpos
 * @param[in] c Should contain -1 if the reason this function is called is because the end of
 *          the current data chunk is reached.
 */
static void htp_urlenp_add_field_piece(htp_urlenp_t *urlenp, const unsigned char *data, size_t startpos, size_t endpos, int last_char) {    
    // Add field if we know it ended (last_char is something other than -1)
    // or if we know that there won't be any more input data (urlenp->_complete is true).
    if ((last_char != -1) || (urlenp->_complete)) {       
        // Prepare the field value, assembling from multiple pieces as necessary.
    
        bstr *field = NULL;

        // Did we use the string builder for this field?
        if (bstr_builder_size(urlenp->_bb) > 0) {            
            // The current field consists of more than once piece, we have to use the string builder.

            // Add current piece to string builder.
            if ((data != NULL) && (endpos - startpos > 0)) {
                bstr_builder_append_mem(urlenp->_bb, data + startpos, endpos - startpos);
            }

            // Generate the field and clear the string builder.
            field = bstr_builder_to_str(urlenp->_bb);
            if (field == NULL) return;

            bstr_builder_clear(urlenp->_bb);
        } else {            
            // We only have the current piece to work with, so no need to involve the string builder.
            if ((data != NULL) && (endpos - startpos > 0)) {
                field = bstr_dup_mem(data + startpos, endpos - startpos);
                if (field == NULL) return;
            }
        }

        // Process field as key or value, as appropriate.
        
        if (urlenp->_state == HTP_URLENP_STATE_KEY) {
            // Key.

            // If there is no more work left to do, then we have a single key. Add it.
            if ((urlenp->_complete)||(last_char == urlenp->argument_separator)) {                
                
                // Handling empty pairs is tricky. We don't want to create a pair for
                // an entirely empty input, but in some cases it may be appropriate
                // (e.g., /index.php?&q=2).
                if ((field != NULL)||(last_char == urlenp->argument_separator)) {
                    // Add one pair, with an empty value and possibly empty key too.

                    bstr *name = field;
                    if (name == NULL) {
                        name = bstr_dup_c("");
                        if (name == NULL) return;
                    }

                    bstr *value = bstr_dup_c("");
                    if (value == NULL) {
                        bstr_free(name);
                        return;
                    }

                    if (urlenp->decode_url_encoding) {
                        htp_tx_urldecode_params_inplace(urlenp->tx, name);
                    }

                    htp_table_addn(urlenp->params, name, value);

                    urlenp->_name = NULL;

                    #ifdef HTP_DEBUG
                    fprint_raw_data(stderr, "NAME", bstr_ptr(name), bstr_len(name));
                    fprint_raw_data(stderr, "VALUE", bstr_ptr(value), bstr_len(value));
                    #endif
                }
            } else {                
                // This key will possibly be followed by a value, so keep it for later.
                urlenp->_name = field;
            }
        } else {            
            // Value (with a key remembered from before).

            bstr *name = urlenp->_name;
            urlenp->_name = NULL;

            if (name == NULL) {
                name = bstr_dup_c("");
                if (name == NULL) {
                    bstr_free(field);
                    return;
                }
            }

            bstr *value = field;
            if (value == NULL) {
                value = bstr_dup_c("");
                if (value == NULL) {
                    bstr_free(name);
                    return;
                }
            }

            if (urlenp->decode_url_encoding) {
                htp_tx_urldecode_params_inplace(urlenp->tx, name);
                htp_tx_urldecode_params_inplace(urlenp->tx, value);
            }

            htp_table_addn(urlenp->params, name, value);           

            #ifdef HTP_DEBUG
            fprint_raw_data(stderr, "NAME", bstr_ptr(name), bstr_len(name));
            fprint_raw_data(stderr, "VALUE", bstr_ptr(value), bstr_len(value));
            #endif
        }        
    } else {
        // The field has not ended. We'll make a copy of of the available data for later.
        if ((data != NULL) && (endpos - startpos > 0)) {
            bstr_builder_append_mem(urlenp->_bb, data + startpos, endpos - startpos);
        }
    }
}

/**
 * Creates a new URLENCODED parser.
 *
 * @return New parser, or NULL on memory allocation failure.
 */
htp_urlenp_t *htp_urlenp_create(htp_tx_t *tx) {
    htp_urlenp_t *urlenp = calloc(1, sizeof (htp_urlenp_t));
    if (urlenp == NULL) return NULL;

    urlenp->tx = tx;

    urlenp->params = htp_table_create(HTP_URLENP_DEFAULT_PARAMS_SIZE);
    if (urlenp->params == NULL) {
        free(urlenp);
        return NULL;
    }

    urlenp->_bb = bstr_builder_create();
    if (urlenp->_bb == NULL) {
        htp_table_destroy(urlenp->params);
        free(urlenp);
        return NULL;
    }

    urlenp->argument_separator = '&';
    urlenp->decode_url_encoding = 1;
    urlenp->_state = HTP_URLENP_STATE_KEY;

    return urlenp;
}

/**
 * Destroys an existing URLENCODED parser.
 * 
 * @param[in] urlenp
 */
void htp_urlenp_destroy(htp_urlenp_t *urlenp) {
    if (urlenp == NULL) return;

    if (urlenp->_name != NULL) {
        bstr_free(urlenp->_name);
    }

    bstr_builder_destroy(urlenp->_bb);

    if (urlenp->params != NULL) {
        // Destroy parameters.
        for (size_t i = 0, n = htp_table_size(urlenp->params); i < n; i++) {
            bstr *b = htp_table_get_index(urlenp->params, i, NULL);
            // Parameter name will be freed by the table code.
            bstr_free(b);
        }

        htp_table_destroy(urlenp->params);
    }

    free(urlenp);
}

/**
 * Finalizes parsing, forcing the parser to convert any outstanding
 * data into parameters. This method should be invoked at the end
 * of a parsing operation that used htp_urlenp_parse_partial().
 *
 * @param[in] urlenp
 * @return Success indication
 */
htp_status_t htp_urlenp_finalize(htp_urlenp_t *urlenp) {
    urlenp->_complete = 1;
    return htp_urlenp_parse_partial(urlenp, NULL, 0);
}

/**
 * Parses the provided data chunk under the assumption
 * that it contains all the data that will be parsed. When this
 * method is used for parsing the finalization method should not
 * be invoked.
 *
 * @param[in] urlenp
 * @param[in] data
 * @param[in] len
 * @return
 */
htp_status_t htp_urlenp_parse_complete(htp_urlenp_t *urlenp, const void *data, size_t len) {
    htp_urlenp_parse_partial(urlenp, data, len);
    return htp_urlenp_finalize(urlenp);
}

/**
 * Parses the provided data chunk, keeping state to allow streaming parsing, i.e., the
 * parsing where only partial information is available at any one time. The method
 * htp_urlenp_finalize() must be invoked at the end to finalize parsing.
 * 
 * @param[in] urlenp
 * @param[in] _data
 * @param[in] len
 * @return
 */
htp_status_t htp_urlenp_parse_partial(htp_urlenp_t *urlenp, const void *_data, size_t len) {
    unsigned char *data = (unsigned char *) _data;
    size_t startpos = 0;
    size_t pos = 0;
    int c;

    if (data == NULL) len = 0;

    do {
        // Get the next character, or use -1 to indicate end of input.
        if (pos < len) c = data[pos];
        else c = -1;

        switch (urlenp->_state) {

            case HTP_URLENP_STATE_KEY:
                // Look for =, argument separator, or end of input.
                if ((c == '=') || (c == urlenp->argument_separator) || (c == -1)) {
                    // Data from startpos to pos.
                    htp_urlenp_add_field_piece(urlenp, data, startpos, pos, c);

                    // If it's not the end of input, then it must be the end of this field.
                    if (c != -1) {
                        // Next state.
                        startpos = pos + 1;

                        if (c == urlenp->argument_separator) {
                            urlenp->_state = HTP_URLENP_STATE_KEY;
                        } else {
                            urlenp->_state = HTP_URLENP_STATE_VALUE;
                        }
                    }
                }

                pos++;

                break;
            
            case HTP_URLENP_STATE_VALUE:
                // Look for argument separator or end of input.
                if ((c == urlenp->argument_separator) || (c == -1)) {
                    // Data from startpos to pos.
                    htp_urlenp_add_field_piece(urlenp, data, startpos, pos, c);

                    // If it's not the end of input, then it must be the end of this field.
                    if (c != -1) {
                        // Next state.
                        startpos = pos + 1;
                        urlenp->_state = HTP_URLENP_STATE_KEY;
                    }
                }

                pos++;

                break;

            default:
                // Invalid state.
                return HTP_ERROR;
        }
    } while (c != -1);

    return HTP_OK;
}
