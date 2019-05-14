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

#ifndef HTP_LIST_H
#define	HTP_LIST_H

#ifdef	__cplusplus
extern "C" {
#endif

// The default list implementation is array-based. The
// linked list version is not fully implemented yet.
#define htp_list_t htp_list_array_t
#define htp_list_add htp_list_array_push
#define htp_list_create htp_list_array_create
#define htp_list_init htp_list_array_init
#define htp_list_clear htp_list_array_clear
#define htp_list_destroy htp_list_array_destroy
#define htp_list_release htp_list_array_release
#define htp_list_get htp_list_array_get
#define htp_list_pop htp_list_array_pop
#define htp_list_push htp_list_array_push
#define htp_list_replace htp_list_array_replace
#define htp_list_size htp_list_array_size
#define htp_list_shift htp_list_array_shift

// Data structures

typedef struct htp_list_array_t htp_list_array_t;
typedef struct htp_list_linked_t htp_list_linked_t;

#include "htp_core.h"
#include "bstr.h"

// Functions

/**
 * Create new array-backed list.
 *
 * @param[in] size
 * @return Newly created list.
 */
htp_list_array_t *htp_list_array_create(size_t size);

/**
 * Initialize an array-backed list.
 *
 * @param[in] l
 * @param[in] size
 * @return HTP_OK or HTP_ERROR if allocation failed
 */
htp_status_t htp_list_array_init(htp_list_array_t *l, size_t size);

/**
 * Remove all elements from the list. It is the responsibility of the caller
 * to iterate over list elements and deallocate them if necessary, prior to
 * invoking this function.
 *
 * @param[in] l
 */
void htp_list_array_clear(htp_list_array_t *l);

/**
 * Free the memory occupied by this list. This function assumes
 * the elements held by the list were freed beforehand.
 *
 * @param[in] l
 */
void htp_list_array_destroy(htp_list_array_t *l);

/**
 * Free the memory occupied by this list, except itself.
 * This function assumes the elements held by the list
 * were freed beforehand.
 *
 * @param[in] l
 */
void htp_list_array_release(htp_list_array_t *l);

/**
 * Find the element at the given index.
 *
 * @param[in] l
 * @param[in] idx
 * @return the desired element, or NULL if the list is too small, or
 *         if the element at that position carries a NULL
 */
void *htp_list_array_get(const htp_list_array_t *l, size_t idx);

/**
 * Remove one element from the end of the list.
 *
 * @param[in] l
 * @return The removed element, or NULL if the list is empty.
 */
void *htp_list_array_pop(htp_list_array_t *l);

/**
 * Add new element to the end of the list, expanding the list as necessary.
 *
 * @param[in] l
 * @param[in] e
 * @return HTP_OK on success or HTP_ERROR on failure.
 *
 */
htp_status_t htp_list_array_push(htp_list_array_t *l, void *e);

/**
 * Replace the element at the given index with the provided element.
 *
 * @param[in] l
 * @param[in] idx
 * @param[in] e
 *
 * @return HTP_OK if an element with the given index was replaced; HTP_ERROR
 *         if the desired index does not exist.
 */
htp_status_t htp_list_array_replace(htp_list_array_t *l, size_t idx, void *e);

/**
 * Returns the size of the list.
 *
 * @param[in] l
 * @return List size.
 */
size_t htp_list_array_size(const htp_list_array_t *l);

/**
 * Remove one element from the beginning of the list.
 *
 * @param[in] l
 * @return The removed element, or NULL if the list is empty.
 */
void *htp_list_array_shift(htp_list_array_t *l);


// Linked list

/**
 * Create a new linked list.
 *
 * @return The newly created list, or NULL on memory allocation failure
 */
htp_list_linked_t *htp_list_linked_create(void);

/**
 * Destroy list. This function will not destroy any of the
 * data stored in it. You'll have to do that manually beforehand.
 *
 * @param[in] l
 */
void htp_list_linked_destroy(htp_list_linked_t *l);

/**
 * Is the list empty?
 *
 * @param[in] l
 * @return 1 if the list is empty, 0 if it is not
 */
int htp_list_linked_empty(const htp_list_linked_t *l);

/**
 * Remove one element from the end of the list.
 *
 * @param[in] l
 * @return Pointer to the removed element, or NULL if the list is empty.
 */
void *htp_list_linked_pop(htp_list_linked_t *l);

/**
 * Add element to list.
 *
 * @param[in] l
 * @param[in] e
 * @return HTP_OK on success, HTP_ERROR on error.
 */
htp_status_t htp_list_linked_push(htp_list_linked_t *l, void *e);

/**
 * Remove one element from the beginning of the list.
 *
 * @param[in] l
 * @return Pointer to the removed element, or NULL if the list is empty.
 */
void *htp_list_linked_shift(htp_list_linked_t *l);

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_LIST_H */

