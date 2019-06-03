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

#ifndef HTP_TABLE_H
#define	HTP_TABLE_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct htp_table_t htp_table_t;

/**
 * Add a new element to the table. The key will be copied, and the copy
 * managed by the table. The table keeps a pointer to the element. It is the
 * callers responsibility to ensure the pointer remains valid.
 *
 * @param[in] table
 * @param[in] key
 * @param[in] element
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_table_add(htp_table_t *table, const bstr *key, const void *element);

/**
 * Add a new element to the table. The key provided will be adopted and managed
 * by the table. You should not keep a copy of the pointer to the key unless you're
 * certain that the table will live longer that the copy. The table keeps a pointer
 * to the element. It is the callers responsibility to ensure the pointer remains
 * valid.
 *
 * @param[in] table
 * @param[in] key
 * @param[in] element
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_table_addn(htp_table_t *table, const bstr *key, const void *element);

/**
 * Add a new element to the table. The key provided will be only referenced and the
 * caller remains responsible to keep it alive until after the table is destroyed. The
 * table keeps a pointer to the element. It is the callers responsibility to ensure
 * the pointer remains valid.
 *
 * @param[in] table
 * @param[in] key
 * @param[in] element
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_table_addk(htp_table_t *table, const bstr *key, const void *element);

/**
 * Remove all elements from the table. This function handles keys
 * according to the active allocation strategy. If the elements need freeing,
 * you need to free them before invoking this function.
 *
 * @param[in] table
 */
void htp_table_clear(htp_table_t *table);

/**
 * Create a new table structure. The table will grow automatically as needed,
 * but you are required to provide a starting size.
 *
 * @param[in] size The starting size.
 * @return Newly created table instance, or NULL on failure.
 */
htp_table_t *htp_table_create(size_t size);

/**
 * Destroy a table. This function handles the keys according to the active
 * allocation strategy. If the elements need freeing, you need to free them
 * before invoking this function. After the table has been destroyed,
 * the pointer is set to NULL.
 *
 * @param[in]   table
 */
void htp_table_destroy(htp_table_t *table);

/**
 * Destroy the given table, but don't free the keys. even if they are managed by
 * the table. Use this method when the responsibility for the keys has been transferred
 * elsewhere. After the table has been destroyed, the pointer is set to NULL.
 *
 * @param[in] table
 */
void htp_table_destroy_ex(htp_table_t *table);

/**
 * Retrieve the first element that matches the given bstr key.
 *
 * @param[in] table
 * @param[in] key
 * @return Matched element, or NULL if no elements match the key.
 */
void *htp_table_get(const htp_table_t *table, const bstr *key);

/**
 * Retrieve the first element that matches the given NUL-terminated key.
 *
 * @param[in] table
 * @param[in] ckey
 * @return Matched element, or NULL if no elements match the key.
 */
void *htp_table_get_c(const htp_table_t *table, const char *ckey);

/**
 * Retrieve key and element at the given index.
 *
 * @param[in] table
 * @param[in] idx
 * @param[in,out] key Pointer in which the key will be returned. Can be NULL.
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
void *htp_table_get_index(const htp_table_t *table, size_t idx, bstr **key);

/**
 * Retrieve table key defined by the provided pointer and length.
 *
 * @param[in] table
 * @param[in] key
 * @param[in] key_len
 * @return Matched element, or NULL if no elements match the key.
 */
void *htp_table_get_mem(const htp_table_t *table, const void *key, size_t key_len);

/**
 * Return the size of the table.
 *
 * @param[in] table
 * @return table size
 */
size_t htp_table_size(const htp_table_t *table);

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_TABLE_H */

