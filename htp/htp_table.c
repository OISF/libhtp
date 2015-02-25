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

static htp_status_t _htp_table_add(htp_table_t *table, const bstr *key, const void *element) {
    // Add key.
    if (htp_list_add(table->list, (void *)key) != HTP_OK) return HTP_ERROR;

    // Add element.
    if (htp_list_add(table->list, (void *)element) != HTP_OK) {
        htp_list_pop(table->list);
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_table_add(htp_table_t *table, const bstr *key, const void *element) {
    if ((table == NULL)||(key == NULL)) return HTP_ERROR;
    
    // Keep track of how keys are allocated, and
    // ensure that all invocations are consistent.
    if (table->alloc_type == HTP_TABLE_KEYS_ALLOC_UKNOWN) {
        table->alloc_type = HTP_TABLE_KEYS_COPIED;
    } else {
        if (table->alloc_type != HTP_TABLE_KEYS_COPIED) {
            #ifdef HTP_DEBUG
            fprintf(stderr, "# Inconsistent key management strategy. Actual %d. Attempted %d.\n",
                table->alloc_type, HTP_TABLE_KEYS_COPIED);
            #endif
            
            return HTP_ERROR;
        }
    }

    bstr *dupkey = bstr_dup(key);
    if (dupkey == NULL) return HTP_ERROR;

    if (_htp_table_add(table, dupkey, element) != HTP_OK) {
        bstr_free(dupkey);
        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_table_addn(htp_table_t *table, const bstr *key, const void *element) {
    if ((table == NULL)||(key == NULL)) return HTP_ERROR;
    
    // Keep track of how keys are allocated, and
    // ensure that all invocations are consistent.
    if (table->alloc_type == HTP_TABLE_KEYS_ALLOC_UKNOWN) {
        table->alloc_type = HTP_TABLE_KEYS_ADOPTED;
    } else {
        if (table->alloc_type != HTP_TABLE_KEYS_ADOPTED) {
            #ifdef HTP_DEBUG
            fprintf(stderr, "# Inconsistent key management strategy. Actual %d. Attempted %d.\n",
                table->alloc_type, HTP_TABLE_KEYS_ADOPTED);
            #endif

            return HTP_ERROR;
        }
    }

    return _htp_table_add(table, key, element);
}

htp_status_t htp_table_addk(htp_table_t *table, const bstr *key, const void *element) {
    if ((table == NULL)||(key == NULL)) return HTP_ERROR;
    
    // Keep track of how keys are allocated, and
    // ensure that all invocations are consistent.
    if (table->alloc_type == HTP_TABLE_KEYS_ALLOC_UKNOWN) {
        table->alloc_type = HTP_TABLE_KEYS_REFERENCED;
    } else {
        if (table->alloc_type != HTP_TABLE_KEYS_REFERENCED) {
            #ifdef HTP_DEBUG
            fprintf(stderr, "# Inconsistent key management strategy. Actual %d. Attempted %d.\n",
                table->alloc_type, HTP_TABLE_KEYS_REFERENCED);
            #endif

            return HTP_ERROR;
        }
    }

    return _htp_table_add(table, key, element);
}

void htp_table_clear(htp_table_t *table) {
    if (table == NULL) return;

    // Free the table keys, but only if we're managing them.
    if ((table->alloc_type == HTP_TABLE_KEYS_COPIED)||(table->alloc_type == HTP_TABLE_KEYS_ADOPTED)) {
        bstr *key = NULL;
        for (size_t i = 0, n = htp_list_size(table->list); i < n; i += 2) {
            key = htp_list_get(table->list, i);
            bstr_free(key);
        }
    }

    htp_list_clear(table->list);
}

void htp_table_clear_ex(htp_table_t *table) {
    if (table == NULL) return;

    // This function does not free table keys.

    htp_list_clear(table->list);
}

htp_table_t *htp_table_create(size_t size) {
    if (size == 0) return NULL;

    htp_table_t *table = calloc(1, sizeof (htp_table_t));
    if (table == NULL) return NULL;

    table->alloc_type = HTP_TABLE_KEYS_ALLOC_UKNOWN;

    // Use a list behind the scenes.
    table->list = htp_list_array_create(size * 2);
    if (table->list == NULL) {
        free(table);
        return NULL;
    }

    return table;
}

void htp_table_destroy(htp_table_t *table) {
    if (table == NULL) return;

    htp_table_clear(table);

    htp_list_destroy(table->list);
    table->list = NULL;

    free(table);
}

void htp_table_destroy_ex(htp_table_t *table) {
    if (table == NULL) return;

    // Change allocation strategy in order to
    // prevent the keys from being freed.
    table->alloc_type = HTP_TABLE_KEYS_REFERENCED;

    htp_table_destroy(table);
}

void *htp_table_get(const htp_table_t *table, const bstr *key) {
    if ((table == NULL)||(key == NULL)) return NULL;

    // Iterate through the list, comparing
    // keys with the parameter, return data if found.    
    for (size_t i = 0, n = htp_list_size(table->list); i < n; i += 2) {
        bstr *key_candidate = htp_list_get(table->list, i);
        void *element = htp_list_get(table->list, i + 1);
        if (bstr_cmp_nocase(key_candidate, key) == 0) {
            return element;
        }
    }

    return NULL;
}

void *htp_table_get_c(const htp_table_t *table, const char *ckey) {
    if ((table == NULL)||(ckey == NULL)) return NULL;

    // Iterate through the list, comparing
    // keys with the parameter, return data if found.    
    for (size_t i = 0, n = htp_list_size(table->list); i < n; i += 2) {
        bstr *key_candidate = htp_list_get(table->list, i);
        void *element = htp_list_get(table->list, i + 1);
        if (bstr_cmp_c_nocase(key_candidate, ckey) == 0) {
            return element;
        }
    }

    return NULL;
}

void *htp_table_get_index(const htp_table_t *table, size_t idx, bstr **key) {
    if (table == NULL) return NULL;
    
    if (idx >= htp_list_size(table->list)) return NULL;

    if (key != NULL) {
        *key = htp_list_get(table->list, idx * 2);
    }

    return htp_list_get(table->list, (idx * 2) + 1);
}

void *htp_table_get_mem(const htp_table_t *table, const void *key, size_t key_len) {
    if ((table == NULL)||(key == NULL)) return NULL;

    // Iterate through the list, comparing
    // keys with the parameter, return data if found.
    for (size_t i = 0, n = htp_list_size(table->list); i < n; i += 2) {
        bstr *key_candidate = htp_list_get(table->list, i);
        void *element = htp_list_get(table->list, i + 1);
        if (bstr_cmp_mem_nocase(key_candidate, key, key_len) == 0) {
            return element;
        }
    }

    return NULL;
}

size_t htp_table_size(const htp_table_t *table) {
    if (table == NULL) return 0;
    return htp_list_size(table->list) / 2;
}
