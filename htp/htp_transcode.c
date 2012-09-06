/***************************************************************************
 * Copyright (c) 2009-2010, Open Information Security Foundation
 * Copyright (c) 2009-2012, Qualys, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the Qualys, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

#include <errno.h>

#include "htp.h"

/**
 * Transcode all parameters supplied in the table.
 *
 * @param connp
 * @param params
 * @param destroy_old
 */
int htp_transcode_params(htp_connp_t *connp, table_t **params, int destroy_old) {
    table_t *input_params = *params;

    // No transcoding unless necessary
    if (connp->cfg->internal_encoding == NULL) {
        return HTP_OK;
    }

    // Create a new table that will hold transcoded parameters
    table_t *output_params = connp->cfg->create_table(table_size(input_params));
    if (output_params == NULL) {
        return HTP_ERROR;
    }
    
    // Initialize iconv
    iconv_t cd = iconv_open(connp->cfg->internal_encoding, connp->cfg->request_encoding);
    if (cd == (iconv_t) -1) {
        // TODO Report iconv initialization error
        table_destroy(&output_params);
        return HTP_ERROR;
    }

    #if (_LIBICONV_VERSION >= 0x0108)
    int iconv_param = 0;
    iconvctl(cd, ICONV_SET_TRANSLITERATE, &iconv_param);
    iconv_param = 1;
    iconvctl(cd, ICONV_SET_DISCARD_ILSEQ, &iconv_param);
    #endif
    
    // Convert the parameters, one by one
    bstr *name = NULL;
    bstr *value = NULL;
    table_iterator_reset(input_params);
    while ((name = table_iterator_next(input_params, (void **) & value)) != NULL) {
        bstr *new_name = NULL, *new_value = NULL;
        
        // Convert name
        htp_transcode_bstr(cd, name, &new_name);
        if (new_name == NULL) {
            iconv_close(cd);
            
            table_iterator_reset(output_params);
            while(table_iterator_next(output_params, (void **) & value) != NULL) {
                bstr_free(&value);
            }
            
            table_destroy(&output_params);
            return HTP_ERROR;
        }
        
        // Convert value        
        htp_transcode_bstr(cd, value, &new_value);
        if (new_value == NULL) {
            bstr_free(&new_name);
            iconv_close(cd);
            
            table_iterator_reset(output_params);
            while(table_iterator_next(output_params, (void **) & value) != NULL) {
                bstr_free(&value);
            }
            
            table_destroy(&output_params);
            return HTP_ERROR;
        }
        
        // Add to new table
        table_addn(output_params, new_name, new_value);
    }
    
    // Replace the old parameter table
    *params = output_params;

    // Destroy the old parameter table if necessary
    if (destroy_old) {
        table_iterator_reset(input_params);
        while(table_iterator_next(input_params, (void **) & value) != NULL) {
            bstr_free(&value);
        }      
    
        table_destroy(&input_params);
    }
    
    iconv_close(cd);

    return HTP_OK;
}

/**
 * Transcode one bstr.
 *
 * @param cd
 * @param input
 * @param output
 */
int htp_transcode_bstr(iconv_t cd, bstr *input, bstr **output) {
    // Reset conversion state for every new string
    iconv(cd, NULL, 0, NULL, 0);

    bstr_builder_t *bb = NULL;

    size_t buflen = 10;
    char *buf = malloc(buflen);
    if (buf == NULL) {
        return HTP_ERROR;
    }

    char *inbuf = bstr_ptr(input);
    size_t inleft = bstr_len(input);
    char *outbuf = buf;
    size_t outleft = buflen;

    int loop = 1;
    while (loop) {
        loop = 0;

        if (iconv(cd, &inbuf, &inleft, &outbuf, &outleft) == (size_t) - 1) {
            if (errno == E2BIG) {
                // Create bstr builder on-demand
                if (bb == NULL) {
                    bb = bstr_builder_create();
                    if (bb == NULL) {
                        free(buf);
                        return HTP_ERROR;
                    }
                }

                // The output buffer is full
                bstr_builder_append_mem(bb, buf, buflen - outleft);

                outbuf = buf;
                outleft = buflen;

                // Continue in the loop, as there's more work to do
                loop = 1;
            } else {
                // Error
                if (bb != NULL) bstr_builder_destroy(bb);
                free(buf);
                return HTP_ERROR;
            }
        }
    }
    
    if (bb != NULL) {
        bstr_builder_append_mem(bb, buf, buflen - outleft);
        *output = bstr_builder_to_str(bb);
        bstr_builder_destroy(bb);
        if (*output == NULL) {
            free(buf);
            return HTP_ERROR;
        }
    } else {
        *output = bstr_dup_mem(buf, buflen - outleft);
        if (*output == NULL) {
            free(buf);
            return HTP_ERROR;
        }
    }
    
    free(buf);

    return HTP_OK;
}
