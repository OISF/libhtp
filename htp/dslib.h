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

#ifndef _DSLIB_H
#define	_DSLIB_H

typedef struct list_t list_t;
typedef struct list_array_t list_array_t;
typedef struct list_linked_element_t list_linked_element_t;
typedef struct list_linked_t list_linked_t;
typedef struct table_t table_t;

#include "bstr.h"

#ifdef __cplusplus
extern "C" {
#endif

// IMPORTANT This library is used internally by the parser and you should
//           not rely on it in your code. The implementation may change at
//           any time.

// Lists

#define list_push(L, E) (L)->push(L, E)
#define list_pop(L) (L)->pop(L)
#define list_empty(L) (L)->empty(L)
#define list_get(L, N) (L)->get((list_t *)L, N)
#define list_replace(L, N, E) (L)->replace((list_t *)L, N, E)
#define list_add(L, N) (L)->push(L, N)
#define list_size(L) (L)->size(L)
#define list_iterator_reset(L) (L)->iterator_reset(L)
#define list_iterator_next(L) (L)->iterator_next(L)
#define list_destroy(L) (*(L))->destroy(L)
#define list_shift(L) (L)->shift(L)

#define LIST_COMMON \
    int (*push)(list_t *, void *); \
    void *(*pop)(list_t *); \
    int (*empty)(const list_t *); \
    void *(*get)(const list_t *, size_t index); \
    int (*replace)(list_t *, size_t index, void *); \
    size_t (*size)(const list_t *); \
    void (*iterator_reset)(list_t *); \
    void *(*iterator_next)(list_t *); \
    void (*destroy)(list_t **); \
    void *(*shift)(list_t *)

struct list_t {
    LIST_COMMON;
};

struct list_linked_element_t {
    void *data;
    list_linked_element_t *next;
};

struct list_linked_t {
    LIST_COMMON;

    list_linked_element_t *first;
    list_linked_element_t *last;
};

struct list_array_t {
    LIST_COMMON;

    size_t first;
    size_t last;
    size_t max_size;
    size_t current_size;
    void **elements;

    size_t iterator_index;
};

list_t *list_linked_create(void);
void list_linked_destroy(list_linked_t **_l);

list_t *list_array_create(size_t size);
void list_array_iterator_reset(list_array_t *l);
void *list_array_iterator_next(list_array_t *l);
void list_array_destroy(list_array_t **_l);


// Table
#define table_add(T, K, E) (T)->add(T, K, E)
#define table_addn(T, K, E) (T)->addn(T, K, E)
#define table_set(T, K, E) (T)->set(T, K, E)
#define table_get(T, K) (T)->get(T, K)
#define table_get_c(T, E) (T)->get_c(T, E)
#define table_iterator_reset(T) (T)->iterator_reset(T)
#define table_iterator_next(T, E) (T)->iterator_next(T, E)
#define table_size(T) (T)->size(T)
#define table_destroy(T) (*(T))->destroy(T)
#define table_clear(T) (T)->clear(T)

struct table_t {
    list_t *list;

   int (*add)(table_t *, bstr *, void *);
   int (*addn)(table_t *, bstr *, void *);
#if 0
  void (*set)(table_t *, bstr *, void *);
#endif
 void *(*get)(const table_t *, const bstr *);
 void *(*get_c)(const table_t *, const char *);
  void (*iterator_reset)(table_t *);
 bstr *(*iterator_next)(table_t *, void **);
size_t (*size)(const table_t *t);
  void (*destroy)(table_t **);
  void (*clear)(table_t *);
};

table_t *table_create(size_t size);

#ifdef __cplusplus
}
#endif

#endif	/* _DSLIB_H */

