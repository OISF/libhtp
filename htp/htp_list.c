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

// Array-backed list

htp_list_t *htp_list_array_create(size_t size) {
    // It makes no sense to create a zero-size list.
    if (size == 0) return NULL;

    // Allocate the list structure.
    htp_list_array_t *l = calloc(1, sizeof (htp_list_array_t));
    if (l == NULL) return NULL;

    // Allocate the initial batch of elements.
    l->elements = malloc(size * sizeof (void *));
    if (l->elements == NULL) {
        free(l);
        return NULL;
    }

    // Initialize the structure.
    l->first = 0;
    l->last = 0;
    l->current_size = 0;
    l->max_size = size;

    return (htp_list_t *) l;
}

void htp_list_array_clear(htp_list_array_t *l) {
    if (l == NULL) return;

    // Continue using already allocated memory; just reset the fields.
    l->first = 0;
    l->last = 0;
    l->current_size = 0;
}

void htp_list_array_destroy(htp_list_array_t *l) {
    if (l == NULL) return;

    free(l->elements);
    free(l);
}

void *htp_list_array_get(const htp_list_array_t *l, size_t idx) {
    if (l == NULL) return NULL;    
    if (idx + 1 > l->current_size) return NULL;
    
    if (l->first + idx < l->max_size) {
        return (void *) l->elements[l->first + idx];
    } else {        
        return (void *) l->elements[idx - (l->max_size - l->first)];
    }
}

void *htp_list_array_pop(htp_list_array_t *l) {
    if (l == NULL) return NULL;

    const void *r = NULL;

    if (l->current_size == 0) {
        return NULL;
    }

    size_t pos = l->first + l->current_size - 1;
    if (pos > l->max_size - 1) pos -= l->max_size;

    r = l->elements[pos];
    l->last = pos;

    l->current_size--;

    return (void *) r;
}

htp_status_t htp_list_array_push(htp_list_array_t *l, void *e) {
    if (l == NULL) return HTP_ERROR;

    // Check whether we're full
    if (l->current_size >= l->max_size) {
        size_t new_size = l->max_size * 2;
        void *newblock = NULL;

        if (l->first == 0) {
            // The simple case of expansion is when the first
            // element in the list resides in the first slot. In
            // that case we just add some new space to the end,
            // adjust the max_size and that's that.
            newblock = realloc(l->elements, new_size * sizeof (void *));
            if (newblock == NULL) return HTP_ERROR;
        } else {
            // When the first element is not in the first
            // memory slot, we need to rearrange the order
            // of the elements in order to expand the storage area.
            /* coverity[suspicious_sizeof] */
            newblock = malloc((size_t) (new_size * sizeof (void *)));
            if (newblock == NULL) return HTP_ERROR;

            // Copy the beginning of the list to the beginning of the new memory block
            /* coverity[suspicious_sizeof] */
            memcpy(newblock,
                    (void *) ((char *) l->elements + l->first * sizeof (void *)),
                    (size_t) ((l->max_size - l->first) * sizeof (void *)));

            // Append the second part of the list to the end
            memcpy((void *) ((char *) newblock + (l->max_size - l->first) * sizeof (void *)),
                    (void *) l->elements,
                    (size_t) (l->first * sizeof (void *)));

            free(l->elements);
        }

        l->first = 0;
        l->last = l->current_size;
        l->max_size = new_size;
        l->elements = newblock;
    }

    l->elements[l->last] = e;
    l->current_size++;

    l->last++;
    if (l->last == l->max_size) {
        l->last = 0;
    }

    return HTP_OK;
}

htp_status_t htp_list_array_replace(htp_list_array_t *l, size_t idx, void *e) {
    if (l == NULL) return HTP_ERROR;

    if (idx + 1 > l->current_size) return HTP_DECLINED;

    l->elements[(l->first + idx) % l->max_size] = e;

    return HTP_OK;
}

size_t htp_list_array_size(const htp_list_array_t *l) {
    if (l == NULL) return HTP_ERROR;

    return l->current_size;
}

void *htp_list_array_shift(htp_list_array_t *l) {
    if (l == NULL) return NULL;

    void *r = NULL;

    if (l->current_size == 0) {
        return NULL;
    }

    r = l->elements[l->first];
    l->first++;
    if (l->first == l->max_size) {
        l->first = 0;
    }

    l->current_size--;

    return r;
}

#if 0
// Linked list

htp_list_linked_t *htp_list_linked_create(void) {
    htp_list_linked_t *l = calloc(1, sizeof (htp_list_linked_t));
    if (l == NULL) return NULL;

    return l;
}

void htp_list_linked_destroy(htp_list_linked_t *l) {
    if (l == NULL) return;

    // Free the list structures
    htp_list_linked_element_t *temp = l->first;
    htp_list_linked_element_t *prev = NULL;
    while (temp != NULL) {
        free(temp->data);
        prev = temp;
        temp = temp->next;
        free(prev);
    }

    // Free the list itself
    free(l);
}

int htp_list_linked_empty(const htp_list_linked_t *l) {
    if (!l->first) {
        return 1;
    } else {
        return 0;
    }
}

void *htp_list_linked_pop(htp_list_linked_t *l) {
    void *r = NULL;

    if (!l->first) {
        return NULL;
    }

    // Find the last element
    htp_list_linked_element_t *qprev = NULL;
    htp_list_linked_element_t *qe = l->first;
    while (qe->next != NULL) {
        qprev = qe;
        qe = qe->next;
    }

    r = qe->data;
    free(qe);

    if (qprev != NULL) {
        qprev->next = NULL;
        l->last = qprev;
    } else {
        l->first = NULL;
        l->last = NULL;
    }

    return r;
}

int htp_list_linked_push(htp_list_linked_t *l, void *e) {
    htp_list_linked_element_t *le = calloc(1, sizeof (htp_list_linked_element_t));
    if (le == NULL) return -1;

    // Remember the element
    le->data = e;

    // If the queue is empty, make this element first
    if (!l->first) {
        l->first = le;
    }

    if (l->last) {
        l->last->next = le;
    }

    l->last = le;

    return 1;
}

void *htp_list_linked_shift(htp_list_linked_t *l) {
    void *r = NULL;

    if (!l->first) {
        return NULL;
    }

    htp_list_linked_element_t *le = l->first;
    l->first = le->next;
    r = le->data;

    if (!l->first) {
        l->last = NULL;
    }

    free(le);

    return r;
}
#endif

#if 0

int main(int argc, char **argv) {
    htp_list_t *q = htp_list_array_create(4);

    htp_list_push(q, "1");
    htp_list_push(q, "2");
    htp_list_push(q, "3");
    htp_list_push(q, "4");

    htp_list_shift(q);
    htp_list_push(q, "5");
    htp_list_push(q, "6");

    char *s = NULL;
    while ((s = (char *) htp_list_pop(q)) != NULL) {
        printf("Got: %s\n", s);
    }

    printf("---\n");

    htp_list_push(q, "1");
    htp_list_push(q, "2");
    htp_list_push(q, "3");
    htp_list_push(q, "4");

    while ((s = (char *) htp_list_shift(q)) != NULL) {
        printf("Got: %s\n", s);
    }

    free(q);

    return 0;
}
#endif
