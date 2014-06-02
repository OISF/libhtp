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

#include "htp_buf.h"

htp_status_t htp_buf_add(htp_buf_t *b, void *data, size_t len) {
    if ((b == NULL)||(data == NULL)) return HTP_ERROR;
    if (len == 0) return HTP_OK;

    // We can store only one external chunk at a time.
    if (b->ext_data != NULL) return HTP_ERROR;

    b->ext_data = data;
    b->ext_len = len;

    return HTP_OK;
}

/**
 *
 * @return
 */
htp_buf_t *htp_buf_create(void) {
    htp_buf_t *b = calloc(1, sizeof(htp_buf_t));
    if (b == NULL) return NULL;

    // Do not create the list here; it's created on demand.

    return b;
}

/**
 * 
 */
void htp_buf_destroy(htp_buf_t *b) {
    if (b == NULL) return;

    if (b->chunks != NULL) {
        for (size_t i = 0, n = htp_list_size(b->chunks); i < n; i++) {
            bstr *chunk = htp_list_get(b->chunks, i);
            bstr_free(chunk);
        }
        
        htp_list_destroy(b->chunks);
        b->chunks = NULL;
    }

    free(b);
}

htp_status_t htp_buf_get(htp_buf_t *b, unsigned char **data, size_t *len) {
    if (b->chunks != NULL) {
        // Get the next chunk if we have an unread one.
        if (b->current_chunk_index < htp_list_size(b->chunks)) {
            bstr *chunk = htp_list_get(b->chunks, b->current_chunk_index);

            if (b->current_chunk_index == 0) {
                *data = bstr_ptr(chunk) + b->first_chunk_offset;
                *len = bstr_len(chunk) - b->first_chunk_offset;
            } else {
                *data = bstr_ptr(chunk);
                *len = bstr_len(chunk);
            }

            b->current_chunk_index++;
            
            return HTP_OK;
        }
    }

    // Return the external chunk, if we have it and if not already read.
    if ((b->ext_data != NULL)&&(b->ext_read == 0)) {
        // Return external data.
        *data = b->ext_data;
        *len = b->ext_len;
        b->ext_read = 1;
        return HTP_OK;
    }

    // No data available.
    return HTP_DECLINED;
}

/**
 */
htp_status_t htp_buf_keep(htp_buf_t *b) {
    if (b->ext_data == NULL) return HTP_OK;

    if (b->chunks == NULL) {
        b->chunks = htp_list_create(HTP_BUF_CHUNK_LIST_SIZE);
        if (b->chunks == NULL) return HTP_ERROR;
    }
    
    bstr *copy = bstr_dup_mem(b->ext_data, b->ext_len);
    if (copy == NULL) return HTP_ERROR;

    if (htp_list_push(b->chunks, copy) != HTP_OK) {
        bstr_free(copy);
        return HTP_ERROR;
    }

    b->ext_data = NULL;
    b->ext_len = 0;

    return HTP_OK;
}

