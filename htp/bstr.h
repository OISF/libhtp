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

#ifndef _BSTR_H
#define	_BSTR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bstr_t bstr;

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bstr_builder.h"

// Data structures
    
struct bstr_t {
    /** The length of the string stored in the buffer. */
    size_t len;

    /** The current size of the buffer. If there is extra room in the
     *  buffer the string will be able to expand without reallocation.
     */
    size_t size;

    /** Optional buffer pointer. If this pointer is NULL the string buffer
     *  will immediately follow this structure. If the pointer is not NUL,
     *  it points to the actual buffer used, and there's no data following
     *  this structure.
     */
    unsigned char *realptr;
};


// Defines

#define bstr_len(X) ((*(X)).len)
#define bstr_size(X) ((*(X)).size)
#define bstr_ptr(X) ( ((*(X)).realptr == NULL) ? ((unsigned char *)(X) + sizeof(bstr)) : (unsigned char *)(*(X)).realptr )
#define bstr_realptr(X) ((*(X)).realptr)


// Functions

/**
 * Append source bstring to destination bstring, growing destination if
 * necessary. If the destination bstring is expanded, the pointer will change.
 * You must replace the original destination pointer with the returned one.
 * Destination is not changed on memory allocation failure.
 *
 * @param[in] bdestination
 * @param[in] bsource
 * @return Updated bstring, or NULL on memory allocation failure.
 */
bstr *bstr_add(bstr *bdestination, const bstr *bsource);

/**
 * Append a NUL-terminated source to destination, growing destination if
 * necessary. If the string is expanded, the pointer will change. You must 
 * replace the original destination pointer with the returned one. Destination
 * is not changed on memory allocation failure.
 *
 * @param[in] b
 * @param[in] cstr
 * @return Updated bstring, or NULL on memory allocation failure.
 */
bstr *bstr_add_c(bstr *b, const char *cstr);

/**
 * Append as many bytes from the source to destination bstring. The
 * destination storage will not be expanded if there is not enough space in it
 * already to accommodate all of the data.
 *
 * @param[in] b
 * @param[in] cstr
 * @return The destination bstring.
 */
bstr *bstr_add_c_noex(bstr *b, const char *cstr);

/**
 * Append a memory region to destination, growing destination if necessary. If
 * the string is expanded, the pointer will change. You must replace the
 * original destination pointer with the returned one. Destination is not
 * changed on memory allocation failure.
 *
 * @param[in] b
 * @param[in] data
 * @param[in] len
 * @return Updated bstring, or NULL on memory allocation failure.
 */
bstr *bstr_add_mem(bstr *b, const void *data, size_t len);

/**
 * Append as many bytes from the source to destination bstring. The
 * destination storage will not be expanded if there is not enough space in it
 * already to accommodate all of the data.
 *
 * @param[in] b
 * @param[in] data
 * @param[in] len
 * @return The destination bstring.
 */
bstr *bstr_add_mem_noex(bstr *b, const void *data, size_t len);

/**
 * Append as many bytes from the source bstring to destination bstring. The
 * destination storage will not be expanded if there is not enough space in it
 * already to accommodate all of the data.
 *
 * @param[in] bdestination
 * @param[in] bsource
 * @return The destination bstring.
 */
bstr *bstr_add_noex(bstr *bdestination, const bstr *bsource);

/**
 * Adjust bstring length. You will need to use this method whenever
 * you work directly with the string contents, and end up changing
 * its length by direct structure manipulation.
 *
 * @param[in] b
 * @param[in] newlen
 */
void bstr_adjust_len(bstr *b, size_t newlen);

/**
 * Change the external pointer used by bstring. You will need to use this
 * function only if you're messing with bstr internals. Use with caution.
 *
 * @param[in] b
 * @param[in] newrealptr
 */
void bstr_adjust_realptr(bstr *b, void *newrealptr);

/**
 * Adjust bstring size. This does not change the size of the storage behind
 * the bstring, just changes the field that keeps track of how many bytes
 * there are in the storage. You will need to use this function only if
 * you're messing with bstr internals. Use with caution.
 *
 * @param[in] b
 * @param[in] newsize
 */
void bstr_adjust_size(bstr *b, size_t newsize);

/**
 * Allocate a zero-length bstring, reserving space for at least size bytes.
 *
 * @param[in] size
 * @return New string instance
 */
bstr *bstr_alloc(size_t size);

/**
 * Checks whether bstring begins with another bstring. Case sensitive.
 * 
 * @param[in] bhaystack
 * @param[in] bneedle
 * @return 1 if true, otherwise 0.
 */
int bstr_begins_with(const bstr *bhaystack, const bstr *bneedle);

/**
 * Checks whether bstring begins with NUL-terminated string. Case sensitive.
 *
 * @param[in] bhaystack
 * @param[in] cneedle
 * @return 1 if true, otherwise 0.
 */
int bstr_begins_with_c(const bstr *bhaystack, const char *cneedle);

/**
 * Checks whether bstring begins with NUL-terminated string. Case insensitive.
 *
 * @param[in] bhaystack
 * @param[in] cneedle
 * @return 1 if true, otherwise 0.
 */
int bstr_begins_with_c_nocase(const bstr *bhaystack, const char *cneedle);

/**
 * Checks whether the bstring begins with the given memory block. Case sensitive.
 *
 * @param[in] bhaystack
 * @param[in] data
 * @param[in] len
 * @return 1 if true, otherwise 0.
 */
int bstr_begins_with_mem(const bstr *bhaystack, const void *data, size_t len);

/**
 * Checks whether bstring begins with memory block. Case insensitive.
 *
 * @param[in] bhaystack
 * @param[in] data
 * @param[in] len
 * @return 1 if true, otherwise 0.
 */
int bstr_begins_with_mem_nocase(const bstr *bhaystack, const void *data, size_t len);

/**
 * Checks whether bstring begins with another bstring. Case insensitive.
 *
 * @param[in] bhaystack
 * @param[in] cneedle
 * @return 1 if true, otherwise 0.
 */
int bstr_begins_with_nocase(const bstr *bhaystack, const bstr *cneedle);

/**
 * Return the byte at the given position.
 *
 * @param[in] b
 * @param[in] pos
 * @return The byte at the given location, or -1 if the position is out of range.
 */
int bstr_char_at(const bstr *b, size_t pos);

/**
 * Return the byte at the given position, counting from the end of the string (e.g.,
 * byte at position 0 is the last byte in the string.)
 *
 * @param[in] b
 * @param[in] pos
 * @return The byte at the given location, or -1 if the position is out of range.
 */
int bstr_char_at_end(const bstr *b, size_t pos);

/**
 * Remove the last byte from bstring, assuming it contains at least one byte. This
 * function will not reduce the storage that backs the string, only the amount
 * of data used.
 *
 * @param[in] b
 */
void bstr_chop(bstr *b);

/**
 * Return the first position of the provided byte.
 *
 * @param[in] b
 * @param[in] c
 * @return The first position of the byte, or -1 if it could not be found
 */
int bstr_chr(const bstr *b, int c);

/**
 * Case-sensitive comparison of two bstrings.
 *
 * @param[in] b1
 * @param[in] b2
 * @return Zero on string match, 1 if b1 is greater than b2, and -1 if b2 is
 *         greater than b1.
 */
int bstr_cmp(const bstr *b1, const bstr *b2);
  
/**
 * Case-sensitive comparison of a bstring and a NUL-terminated string.
 *
 * @param[in] b
 * @param[in] cstr
 * @return Zero on string match, 1 if b is greater than cstr, and -1 if cstr is
 *         greater than b.
 */
int bstr_cmp_c(const bstr *b, const char *cstr);

/**
 * Case-insensitive comparison of a bstring with a NUL-terminated string.
 *
 * @param[in] b
 * @param[in] cstr
 * @return Zero on string match, 1 if b is greater than cstr, and -1 if cstr is greater than b.
 */
int bstr_cmp_c_nocase(const bstr *b, const char *cstr);

/**
 * Case-insensitive zero-skipping comparison of a bstring with a NUL-terminated string.
 *
 * @param[in] b
 * @param[in] cstr
 * @return Zero on string match, 1 if b is greater than cstr, and -1 if cstr is greater than b.
 */
int bstr_cmp_c_nocasenorzero(const bstr *b, const char *cstr);

/**
 * Performs a case-sensitive comparison of a bstring with a memory region.
 *
 * @param[in] b
 * @param[in] data
 * @param[in] len
 * @return Zero ona match, 1 if b is greater than data, and -1 if data is greater than b.
 */
int bstr_cmp_mem(const bstr *b, const void *data, size_t len);

/**
 * Performs a case-insensitive comparison of a bstring with a memory region.
 *
 * @param[in] b
 * @param[in] data
 * @param[in] len
 * @return Zero ona match, 1 if b is greater than data, and -1 if data is greater than b.
 */
int bstr_cmp_mem_nocase(const bstr *b, const void *data, size_t len);

/**
 * Case-insensitive comparison two bstrings.
 *
 * @param[in] b1
 * @param[in] b2
 * @return Zero on string match, 1 if b1 is greater than b2, and -1 if b2 is
 *         greater than b1.
 */
int bstr_cmp_nocase(const bstr *b1, const bstr *b2);

/**
 * Case-insensitive and zero skipping comparison two bstrings.
 *
 * @param[in] b1
 * @param[in] b2
 * @return Zero on string match, 1 if b1 is greater than b2, and -1 if b2 is
 *         greater than b1.
 */
int bstr_cmp_nocasenorzero(const bstr *b1, const bstr *b2);

/**
 * Create a new bstring by copying the provided bstring.
 *
 * @param[in] b
 * @return New bstring, or NULL if memory allocation failed.
 */
bstr *bstr_dup(const bstr *b);

/**
 * Create a new bstring by copying the provided NUL-terminated string.
 *
 * @param[in] cstr
 * @return New bstring, or NULL if memory allocation failed.
 */
bstr *bstr_dup_c(const char *cstr);

/**
 * Create a new bstring by copying a part of the provided bstring.
 *
 * @param[in] b
 * @param[in] offset
 * @param[in] len
 * @return New bstring, or NULL if memory allocation failed.
 */
bstr *bstr_dup_ex(const bstr *b, size_t offset, size_t len);

/**
 * Create a copy of the provided bstring, then convert it to lowercase.
 *
 * @param[in] b
 * @return New bstring, or NULL if memory allocation failed
 */
bstr *bstr_dup_lower(const bstr *b);

/**
 * Create a new bstring by copying the provided memory region.
 *
 * @param[in] data
 * @param[in] len
 * @return New bstring, or NULL if memory allocation failed
 */
bstr *bstr_dup_mem(const void *data, size_t len);

/**
 * Expand internal bstring storage to support at least newsize bytes. The storage
 * is not expanded if the current size is equal or greater to newsize. Because
 * realloc is used underneath, the old pointer to bstring may no longer be valid
 * after this function completes successfully.
 *
 * @param[in] b
 * @param[in] newsize
 * @return Updated string instance, or NULL if memory allocation failed or if
 *         attempt was made to "expand" the bstring to a smaller size.
 */
bstr *bstr_expand(bstr *b, size_t newsize);

/**
 * Deallocate the supplied bstring instance and set it to NULL. Allows NULL on
 * input.
 *
 * @param[in] b
 */
void bstr_free(bstr *b);

/**
 * Find the needle in the haystack.
 *
 * @param[in] bhaystack
 * @param[in] bneedle
 * @return Position of the match, or -1 if the needle could not be found.
 */
int bstr_index_of(const bstr *bhaystack, const bstr *bneedle);

/**
 * Find the needle in the haystack, ignoring case differences.
 *
 * @param[in] bhaystack
 * @param[in] bneedle
 * @return Position of the match, or -1 if the needle could not be found.
 */
int bstr_index_of_nocase(const bstr *bhaystack, const bstr *bneedle);

/**
 * Find the needle in the haystack, with the needle being a NUL-terminated
 * string.
 *
 * @param[in] bhaystack
 * @param[in] cneedle
 * @return Position of the match, or -1 if the needle could not be found.
 */
int bstr_index_of_c(const bstr *bhaystack, const char *cneedle);

/**
 * Find the needle in the haystack, with the needle being a NUL-terminated
 * string. Ignore case differences.
 *
 * @param[in] bhaystack
 * @param[in] cneedle
 * @return Position of the match, or -1 if the needle could not be found.
 */
int bstr_index_of_c_nocase(const bstr *bhaystack, const char *cneedle);

/**
 * Find the needle in the haystack, with the needle being a NUL-terminated
 * string. Ignore case differences. Skip zeroes in haystack
 *
 * @param[in] bhaystack
 * @param[in] cneedle
 * @return Position of the match, or -1 if the needle could not be found.
 */
int bstr_index_of_c_nocasenorzero(const bstr *bhaystack, const char *cneedle);

/**
 * Find the needle in the haystack, with the needle being a memory region.
 *
 * @param[in] bhaystack
 * @param[in] data
 * @param[in] len
 * @return Position of the match, or -1 if the needle could not be found.
 */
int bstr_index_of_mem(const bstr *bhaystack, const void *data, size_t len);

/**
 * Find the needle in the haystack, with the needle being a memory region.
 * Ignore case differences.
 *
 * @param[in] bhaystack
 * @param[in] data
 * @param[in] len
 * @return Position of the match, or -1 if the needle could not be found.
 */
int bstr_index_of_mem_nocase(const bstr *bhaystack, const void *data, size_t len);

/**
 * Return the last position of a character (byte).
 *
 * @param[in] b
 * @param[in] c
 * @return The last position of the character, or -1 if it could not be found.
 */
int bstr_rchr(const bstr *b, int c);

/**
 * Convert bstring to lowercase. This function converts the supplied string,
 * it does not create a new string.
 *
 * @param[in] b
 * @return The same bstring received on input
 */
bstr *bstr_to_lowercase(bstr *b);

/**
 * Case-sensitive comparison of two memory regions.
 *
 * @param[in] data1
 * @param[in] len1
 * @param[in] data2
 * @param[in] len2
 * @return Zero if the memory regions are identical, 1 if data1 is greater than
 *         data2, and -1 if data2 is greater than data1.
 */
int bstr_util_cmp_mem(const void *data1, size_t len1, const void *data2, size_t len2);

/**
 * Case-insensitive comparison of two memory regions.
 *
 * @param[in] data1
 * @param[in] len1
 * @param[in] data2
 * @param[in] len2
 * @return Zero if the memory regions are identical, 1 if data1 is greater than
 *         data2, and -1 if data2 is greater than data1.
 */
 int bstr_util_cmp_mem_nocase(const void *data1, size_t len1, const void *data2, size_t len2);

/**
 * Case-insensitive zero-skipping comparison of two memory regions.
 *
 * @param[in] data1
 * @param[in] len1
 * @param[in] data2
 * @param[in] len2
 * @return Zero if the memory regions are identical, 1 if data1 is greater than
 *         data2, and -1 if data2 is greater than data1.
 */
 int bstr_util_cmp_mem_nocasenorzero(const void *data1, size_t len1, const void *data2, size_t len2);

/**
 * Convert contents of a memory region to a positive integer.
 *
 * @param[in] data
 * @param[in] len
 * @param[in] base The desired number base.
 * @param[in] lastlen Points to the first unused byte in the region
 * @return If the conversion was successful, this function returns the
 *         number. When the conversion fails, -1 will be returned when not
 *         one valid digit was found, and -2 will be returned if an overflow
 *         occurred.
 */   
int64_t bstr_util_mem_to_pint(const void *data, size_t len, int base, size_t *lastlen);

/**
 * Searches a memory block for the given NUL-terminated string. Case sensitive.
 *
 * @param[in] data
 * @param[in] len
 * @param[in] cstr
 * @return Index of the first location of the needle on success, or -1 if the needle was not found.
 */
int bstr_util_mem_index_of_c(const void *data, size_t len, const char *cstr);

/**
 * Searches a memory block for the given NUL-terminated string. Case insensitive.
 *
 * @param[in] data
 * @param[in] len
 * @param[in] cstr
 * @return Index of the first location of the needle on success, or -1 if the needle was not found.
 */
int bstr_util_mem_index_of_c_nocase(const void *data, size_t len, const char *cstr);

/**
 * Searches the haystack memory block for the needle memory block. Case sensitive.
 *
 * @param data1
 * @param len1
 * @param data2
 * @param len2
 * @return Index of the first location of the needle on success, or -1 if the needle was not found.
 */
int bstr_util_mem_index_of_mem(const void *data1, size_t len1, const void *data2, size_t len2);

/**
 * Searches the haystack memory block for the needle memory block. Case sensitive.
 *
 * @param data1
 * @param len1
 * @param data2
 * @param len2
 * @return Index of the first location of the needle on success, or -1 if the needle was not found.
 */
int bstr_util_mem_index_of_mem_nocase(const void *data1, size_t len1, const void *data2, size_t len2);

/**
 * Searches the haystack memory block for the needle memory block. Case sensitive. Skips zeroes in data1
 *
 * @param data1
 * @param len1
 * @param data2
 * @param len2
 * @return Index of the first location of the needle on success, or -1 if the needle was not found.
 */
int bstr_util_mem_index_of_mem_nocasenorzero(const void *data1, size_t len1, const void *data2, size_t len2);

/**
 * Removes whitespace from the beginning and the end of a memory region. The data
 * itself is not modified; this function only adjusts the provided pointers.
 *
 * @param[in,out] data
 * @param[in,out] len
 */
void bstr_util_mem_trim(unsigned char **data, size_t *len);

/**
 * Take the provided memory region, allocate a new memory buffer, and construct
 * a NUL-terminated string, replacing each NUL byte with "\0" (two bytes). The
 * caller is responsible to keep track of the allocated memory area and free
 * it once it is no longer needed.
 *
 * @param[in] data
 * @param[in] len
 * @return The newly created NUL-terminated string, or NULL in case of memory
 *         allocation failure.
 */
char *bstr_util_memdup_to_c(const void *data, size_t len);

/**
 * Create a new NUL-terminated string out of the provided bstring. If NUL bytes
 * are contained in the bstring, each will be replaced with "\0" (two characters).
 * The caller is responsible to keep track of the allocated memory area and free
 * it once it is no longer needed.
 *
 * @param[in] b
 * @return The newly created NUL-terminated string, or NULL in case of memory
 *         allocation failure.
 */
char *bstr_util_strdup_to_c(const bstr *b);
  
/**
 * Create a new bstring from the provided NUL-terminated string and without
 * copying the data. The caller must ensure that the input string continues
 * to point to a valid memory location for as long as the bstring is used.
 * 
 * @param[in] cstr
 * @return New bstring, or NULL on memory allocation failure.
 */
bstr *bstr_wrap_c(const char *cstr);

/**
 * Create a new bstring from the provided memory buffer without
 * copying the data. The caller must ensure that the buffer remains
 * valid for as long as the bstring is used.
 *
 * @param[in] data
 * @param[in] len
 * @return New bstring, or NULL on memory allocation failure.
 */
bstr *bstr_wrap_mem(const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif	/* _BSTR_H */
