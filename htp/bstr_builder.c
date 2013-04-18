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

#include "bstr.h"
#include "htp_list.h"

htp_status_t bstr_builder_appendn(bstr_builder_t *bb, bstr *b) {
    return htp_list_push(bb->pieces, b);
}

htp_status_t bstr_builder_append_c(bstr_builder_t *bb, const char *cstr) {
    bstr *b = bstr_dup_c(cstr);
    if (b == NULL) return HTP_ERROR;
    return htp_list_push(bb->pieces, b);
}

htp_status_t bstr_builder_append_mem(bstr_builder_t *bb, const void *data, size_t len) {
    bstr *b = bstr_dup_mem(data, len);
    if (b == NULL) return HTP_ERROR;
    return htp_list_push(bb->pieces, b);
}

void bstr_builder_clear(bstr_builder_t *bb) {    
    // Do nothing if the list is empty
    if (htp_list_size(bb->pieces) == 0) return;

    for (size_t i = 0, n = htp_list_size(bb->pieces); i < n; i++) {
        bstr *b = htp_list_get(bb->pieces, i);
        bstr_free(b);
    }

    htp_list_clear(bb->pieces);
}

bstr_builder_t *bstr_builder_create() {
    bstr_builder_t *bb = calloc(1, sizeof (bstr_builder_t));
    if (bb == NULL) return NULL;

    bb->pieces = htp_list_create(BSTR_BUILDER_DEFAULT_SIZE);
    if (bb->pieces == NULL) {
        free(bb);
        return NULL;
    }

    return bb;
}

void bstr_builder_destroy(bstr_builder_t *bb) {
    if (bb == NULL) return;

    // Destroy any pieces we might have
    for (size_t i = 0, n = htp_list_size(bb->pieces); i < n; i++) {
        bstr *b = htp_list_get(bb->pieces, i);
        bstr_free(b);
    }

    htp_list_destroy(bb->pieces);

    free(bb);
}

size_t bstr_builder_size(const bstr_builder_t *bb) {
    return htp_list_size(bb->pieces);
}

bstr *bstr_builder_to_str(const bstr_builder_t *bb) {
    size_t len = 0;

    // Determine the size of the string
    for (size_t i = 0, n = htp_list_size(bb->pieces); i < n; i++) {
        bstr *b = htp_list_get(bb->pieces, i);
        len += bstr_len(b);
    }

    // Allocate string
    bstr *bnew = bstr_alloc(len);
    if (bnew == NULL) return NULL;

    // Determine the size of the string
    for (size_t i = 0, n = htp_list_size(bb->pieces); i < n; i++) {
        bstr *b = htp_list_get(bb->pieces, i);
        bstr_add_noex(bnew, b);
    }

    return bnew;
}
