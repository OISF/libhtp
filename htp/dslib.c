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

#include <stdlib.h>
#include <stdio.h>

#include "dslib.h"


// -- Queue List --

/**
 * Add element to list.
 *
 * @param list
 * @param element
 * @return 1 on success, -1 on error (memory allocation failure)
 */
static int list_linked_push(list_t *_q, void *element) {
    list_linked_t *q = (list_linked_t *) _q;
    list_linked_element_t *qe = calloc(1, sizeof (list_linked_element_t));
    if (qe == NULL) return -1;

    // Remember the element
    qe->data = element;

    // If the queue is empty, make this element first
    if (!q->first) {
        q->first = qe;
    }

    if (q->last) {
        q->last->next = qe;
    }

    q->last = qe;

    return 1;
}

/**
 * Remove one element from the end of the list.
 *
 * @param list
 * @return a pointer to the removed element, or NULL if the list is empty.
 */
static void *list_linked_pop(list_t *_q) {
    list_linked_t *q = (list_linked_t *) _q;
    void *r = NULL;

    if (!q->first) {
        return NULL;
    }

    // Find the last element
    list_linked_element_t *qprev = NULL;
    list_linked_element_t *qe = q->first;
    while(qe->next != NULL) {
        qprev = qe;
        qe = qe->next;
    }

    r = qe->data;
    free(qe);

    if (qprev != NULL) {
        qprev->next = NULL;
        q->last = qprev;
    } else {
        q->first = NULL;
        q->last = NULL;
    }      

    return r;
}

/**
 * Remove one element from the beginning of the list.
 *
 * @param list
 * @return a pointer to the removed element, or NULL if the list is empty.
 */
static void *list_linked_shift(list_t *_q) {
    list_linked_t *q = (list_linked_t *) _q;
    void *r = NULL;

    if (!q->first) {
        return NULL;
    }

    list_linked_element_t *qe = q->first;
    q->first = qe->next;
    r = qe->data;

    if (!q->first) {
        q->last = NULL;
    }

    free(qe);

    return r;
}

/**
 * Is the list empty?
 *
 * @param list
 * @return 1 if the list is empty, 0 if it is not
 */
static int list_linked_empty(const list_t *_q) {
    const list_linked_t *q = (const list_linked_t *) _q;

    if (!q->first) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Destroy list. This function will not destroy any of the
 * data stored in it. You'll have to do that manually beforehand.
 *
 * @param l
 */
void list_linked_destroy(list_linked_t **_l) {
    if ((_l == NULL)||(*_l == NULL)) return;
    
    list_linked_t *l = *_l;
    // Free the list structures
    list_linked_element_t *temp = l->first;
    list_linked_element_t *prev = NULL;
    while (temp != NULL) {
        free(temp->data);
        prev = temp;
        temp = temp->next;
        free(prev);
    }

    // Free the list itself
    free(l);
    *_l = NULL;
}

/**
 * Create a new linked list.
 *
 * @return a pointer to the newly created list (list_t), or NULL on memory allocation failure
 */
list_t *list_linked_create(void) {
    list_linked_t *q = calloc(1, sizeof (list_linked_t));
    if (q == NULL) return NULL;

    q->push = list_linked_push;
    q->pop = list_linked_pop;
    q->empty = list_linked_empty;
    q->destroy = (void (*)(list_t **))list_linked_destroy;
    q->shift = list_linked_shift;

    return (list_t *) q;
}

// -- Queue Array --

/**
 * Add new element to the end of the list, expanding the list
 * as necessary.
 *
 * @param list
 * @param element
 *
 * @return 1 on success or -1 on failure (memory allocation)
 */
static int list_array_push(list_t *_q, void *element) {
    list_array_t *q = (list_array_t *) _q;   

    // Check whether we're full
    if (q->current_size >= q->max_size) {
        size_t new_size = q->max_size * 2;
        void *newblock = NULL;
        
        if (q->first == 0) {
            // The simple case of expansion is when the first
            // element in the list resides in the first slot. In
            // that case we just add some new space to the end,
            // adjust the max_size and that's that.
            newblock = realloc(q->elements, new_size * sizeof (void *));
            if (newblock == NULL) return -1;
        } else {
            // When the first element is not in the first
            // memory slot, we need to rearrange the order
            // of the elements in order to expand the storage area.
            newblock = malloc(new_size * sizeof (void *));
            if (newblock == NULL) return -1;

            // Copy the beginning of the list to the beginning of the new memory block
            memcpy((char *)newblock, (char *)q->elements + q->first * sizeof (void *), (q->max_size - q->first) * sizeof (void *));
            // Append the second part of the list to the end
            memcpy((char *)newblock + (q->max_size - q->first) * sizeof (void *), q->elements, q->first * sizeof (void *));
            
            free(q->elements);
        }
        
        q->first = 0;
        q->last = q->current_size;
        q->max_size = new_size;
        q->elements = newblock;
    }

    q->elements[q->last] = element;
    q->current_size++;
    
    q->last++;
    if (q->last == q->max_size) {
        q->last = 0;
    }

    return 1;
}

/**
 * Remove one element from the end of the list.
 *
 * @param list
 * @return the removed element, or NULL if the list is empty
 */
static void *list_array_pop(list_t *_q) {
    list_array_t *q = (list_array_t *) _q;
    void *r = NULL;   

    if (q->current_size == 0) {
        return NULL;
    }

    size_t pos = q->first + q->current_size - 1;    
    if (pos > q->max_size - 1) pos -= q->max_size;    

    r = q->elements[pos];
    q->last = pos;

    q->current_size--;   

    return r;
}

/**
 * Remove one element from the beginning of the list.
 *
 * @param list
 * @return the removed element, or NULL if the list is empty
 */
static void *list_array_shift(list_t *_q) {
    list_array_t *q = (list_array_t *) _q;
    void *r = NULL;   

    if (q->current_size == 0) {
        return NULL;
    }

    r = q->elements[q->first];
    q->first++;
    if (q->first == q->max_size) {
        q->first = 0;
    }

    q->current_size--;

    return r;
}

/**
 * Returns the size of the list.
 *
 * @param list
 */
static size_t list_array_size(const list_t *_l) {
    return ((const list_array_t *) _l)->current_size;
}

/**
 * Return the element at the given index.
 *
 * @param list
 * @param index
 * @return the desired element, or NULL if the list is too small, or
 *         if the element at that position carries a NULL
 */
static void *list_array_get(const list_t *_l, size_t idx) {
    const list_array_t *l = (const list_array_t *) _l;
    void *r = NULL;

    if (idx + 1 > l->current_size) return NULL;

    size_t i = l->first;
    r = l->elements[l->first];

    while (idx--) {
        if (++i == l->max_size) {
            i = 0;
        }

        r = l->elements[i];
    }

    return r;
}

/**
 * Replace the element at the given index with the provided element.
 *
 * @param list
 * @param index
 * @param element
 *
 * @return 1 if the element was replaced, or 0 if the list is too small
 */
static int list_array_replace(list_t *_l, size_t idx, void *element) {
    list_array_t *l = (list_array_t *) _l;    

    if (idx + 1 > l->current_size) return 0;

    size_t i = l->first;

    while (idx--) {
        if (++i == l->max_size) {
            i = 0;
        }
    }

    l->elements[i] = element;

    return 1;
}

/**
 * Reset the list iterator.
 *
 * @param l
 */
void list_array_iterator_reset(list_array_t *l) {
    l->iterator_index = 0;
}

/**
 * Advance to the next list value.
 *
 * @param l
 * @return the next list value, or NULL if there aren't more elements
 *         left to iterate over or if the element itself is NULL
 */
void *list_array_iterator_next(list_array_t *l) {
    void *r = NULL;

    if (l->iterator_index < l->current_size) {
        r = list_get(l, l->iterator_index);
        l->iterator_index++;
    }

    return r;
}

/**
 * Free the memory occupied by this list. This function assumes
 * the data elements were freed beforehand.
 *
 * @param l
 */
void list_array_destroy(list_array_t **_l) {
    if ((_l == NULL)||(*_l == NULL)) return;

    list_array_t *l = *_l;
    free(l->elements);
    free(l);
    *_l = NULL;
}

/**
 * Create new array-based list.
 *
 * @param size
 * @return newly allocated list (list_t)
 */
list_t *list_array_create(size_t size) {
    // Allocate the list structure
    list_array_t *q = calloc(1, sizeof (list_array_t));
    if (q == NULL) return NULL;

    // Allocate the initial batch of elements
    q->elements = malloc(size * sizeof (void *));
    if (q->elements == NULL) {
        free(q);
        return NULL;
    }

    // Initialise structure
    q->first = 0;
    q->last = 0;
    q->max_size = size;
    q->push = list_array_push;
    q->pop = list_array_pop;
    q->get = list_array_get;
    q->replace = list_array_replace;
    q->size = list_array_size;
    q->iterator_reset = (void (*)(list_t *))list_array_iterator_reset;
    q->iterator_next = (void *(*)(list_t *))list_array_iterator_next;
    q->destroy = (void (*)(list_t **))list_array_destroy;
    q->shift = list_array_shift;

    return (list_t *) q;
}


// -- Table --

/**
 * Add a new table element. This function currently makes a copy of
 * the key, which is inefficient.
 *
 * @param table
 * @param key
 * @param element
 */
static int list_table_add(table_t *table, bstr *key, void *element) {
    bstr *dupkey = bstr_dup(key);
    if (dupkey == NULL) {
        return -1;
    }

    int rc = table_addn(table, dupkey, element);
    if (rc == -1) {
        free(dupkey);
    }

    return rc;
}

static int list_table_addn(table_t *table, bstr *key, void *element) {
    // Add key
    if (list_add(table->list, key) != 1) {    
        return -1;
    }

    // Add element
    if (list_add(table->list, element) != 1) {
        list_pop(table->list);        
        return -1;
    }

    return 1;
}

/**
 * @param table
 * @param key
 */
/*
static void *table_get_internal(table_t *table, bstr *key) {
    // Iterate through the list, comparing
    // keys with the parameter, return data if found.
    bstr *ts = NULL;
    list_iterator_reset(table->list);
    while ((ts = list_iterator_next(table->list)) != NULL) {
        void *data = list_iterator_next(table->list);
        if (bstr_cmp_nocase(ts, key) == 0) {
            return data;
        }
    }

    return NULL;
}
*/

/**
 * Retrieve the first element in the table with the given
 * key (as a NUL-terminated string).
 *
 * @param table
 * @param cstr
 * @return table element, or NULL if not found
 */
static void *list_table_get_c(const table_t *table, const char *cstr) {
    // Iterate through the list, comparing
    // keys with the parameter, return data if found.
    bstr *ts = NULL;
    list_iterator_reset(table->list);
    while ((ts = list_iterator_next(table->list)) != NULL) {
        void *data = list_iterator_next(table->list);
        if (bstr_cmp_c_nocase(ts, cstr) == 0) {
            return data;
        }
    }

    return NULL;
}

/**
 * Retrieve the first element in the table with the given key.
 *
 * @param table
 * @param key
 * @return table element, or NULL if not found
 */
static void *list_table_get(const table_t *table, const bstr *key) {
    // Iterate through the list, comparing
    // keys with the parameter, return data if found.
    bstr *ts = NULL;
    list_iterator_reset(table->list);
    while ((ts = list_iterator_next(table->list)) != NULL) {
        void *data = list_iterator_next(table->list);
        if (bstr_cmp_nocase(ts, key) == 0) {
            return data;
        }
    }

    return NULL;
}

/**
 * Reset the table iterator.
 *
 * @param table
 */
static void list_table_iterator_reset(table_t *table) {
    list_iterator_reset(table->list);
}

/**
 * Advance to the next table element.
 *
 * @param t
 * @param data
 * @return pointer to the key and the element if there is a next element, NULL otherwise
 */
static bstr *list_table_iterator_next(table_t *t, void **data) {
    bstr *s = list_iterator_next(t->list);
    if (s != NULL) {
        *data = list_iterator_next(t->list);
    }

    return s;
}

/**
 * Returns the size of the table.
 *
 * @param table
 * @return table size
 */
static size_t list_table_size(const table_t *table) {
    return list_size(table->list) / 2;
}

/**
 * Remove all elements from the table.
 *
 * @param table
 */
static void list_table_clear(table_t *table) {
    size_t size = list_size(table->list);

    list_destroy(&table->list);
    
    // Use a list behind the scenes
    table->list = list_array_create(size == 0 ? 10 : size);
    if (table->list == NULL) {
        free(table);        
    }    
}

/**
 * Destroy a table.
 *
 * @param table
 */
static void list_table_destroy(table_t **_table) {
    if ((_table == NULL)||(*_table == NULL)) return;

    table_t *table = *_table;
    // Free keys only
    int counter = 0;
    void *data = NULL;

    list_iterator_reset(table->list);

    while ((data = list_iterator_next(table->list)) != NULL) {
        // Free key
        if ((counter % 2) == 0) {
            free(data);
        }

        counter++;
    }

    list_destroy(&table->list);

    free(table);
    *_table = NULL;
}

/**
 * Create a new table structure.
 *
 * @param size
 * @return newly created table_t
 */
table_t *table_create(size_t size) {
    table_t *t = calloc(1, sizeof (table_t));
    if (t == NULL) return NULL;

    // Use a list behind the scenes
    t->list = list_array_create(size * 2);
    if (t->list == NULL) {
        free(t);
        return NULL;
    }

    // Initialise structure
    t->add = list_table_add;
    t->addn = list_table_addn;
#if 0
    t->set = list_table_set;
#endif
    t->get = list_table_get;
    t->get_c = list_table_get_c;
    t->iterator_reset = list_table_iterator_reset;
    t->iterator_next = list_table_iterator_next;
    t->size = list_table_size;
    t->destroy = list_table_destroy;
    t->clear = list_table_clear;

    return t;
}

#if 0

int main(int argc, char **argv) {
    list_t *q = list_array_create(4);

    list_push(q, "1");
    list_push(q, "2");
    list_push(q, "3");
    list_push(q, "4");

    list_shift(q);
    list_push(q, "5");
    list_push(q, "6");

    char *s = NULL;
    while ((s = (char *) list_pop(q)) != NULL) {
        printf("Got: %s\n", s);
    }

    printf("---\n");

    list_push(q, "1");
    list_push(q, "2");
    list_push(q, "3");
    list_push(q, "4");

    while ((s = (char *) list_shift(q)) != NULL) {
        printf("Got: %s\n", s);
    }

    free(q);

    return 0;
}
#endif
