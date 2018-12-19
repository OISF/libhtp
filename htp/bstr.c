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

#include <ctype.h>

#include "bstr.h"

bstr *bstr_alloc(size_t len) {
    bstr *b = malloc(sizeof (bstr) + len);
    if (b == NULL) return NULL;

    b->len = 0;
    b->size = len;
    b->realptr = NULL;

    return b;
}

bstr *bstr_add(bstr *destination, const bstr *source) {
    return bstr_add_mem(destination, bstr_ptr(source), bstr_len(source));
}

bstr *bstr_add_c(bstr *bdestination, const char *csource) {
    return bstr_add_mem(bdestination, csource, strlen(csource));
}

bstr *bstr_add_c_noex(bstr *destination, const char *source) {
    return bstr_add_mem_noex(destination, source, strlen(source));
}

bstr *bstr_add_mem(bstr *destination, const void *data, size_t len) {
    // Expand the destination if necessary
    if (bstr_size(destination) < bstr_len(destination) + len) {
        destination = bstr_expand(destination, bstr_len(destination) + len);
        if (destination == NULL) return NULL;
    }

    // Add source to destination
    bstr *b = (bstr *) destination;
    memcpy(bstr_ptr(destination) + bstr_len(b), data, len);
    bstr_adjust_len(b, bstr_len(b) + len);

    return destination;
}

bstr *bstr_add_mem_noex(bstr *destination, const void *data, size_t len) {
    size_t copylen = len;

    // Is there enough room in the destination?
    if (bstr_size(destination) < bstr_len(destination) + copylen) {
        copylen = bstr_size(destination) - bstr_len(destination);
        if (copylen <= 0) return destination;
    }

    // Copy over the bytes
    bstr *b = (bstr *) destination;
    memcpy(bstr_ptr(destination) + bstr_len(b), data, copylen);
    bstr_adjust_len(b, bstr_len(b) + copylen);

    return destination;
}

bstr *bstr_add_noex(bstr *destination, const bstr *source) {
    return bstr_add_mem_noex(destination, bstr_ptr(source), bstr_len(source));
}

void bstr_adjust_len(bstr *b, size_t newlen) {
    b->len = newlen;
}

void bstr_adjust_realptr(bstr *b, void *newrealptr) {
    b->realptr = newrealptr;
}

void bstr_adjust_size(bstr *b, size_t newsize) {
    b->size = newsize;
}

int bstr_begins_with(const bstr *haystack, const bstr *needle) {
    return bstr_begins_with_mem(haystack, bstr_ptr(needle), bstr_len(needle));
}

int bstr_begins_with_c(const bstr *haystack, const char *needle) {
    return bstr_begins_with_mem(haystack, needle, strlen(needle));
}

int bstr_begins_with_c_nocase(const bstr *haystack, const char *needle) {
    return bstr_begins_with_mem_nocase(haystack, needle, strlen(needle));
}

int bstr_begins_with_nocase(const bstr *haystack, const bstr *needle) {
    return bstr_begins_with_mem_nocase(haystack, bstr_ptr(needle), bstr_len(needle));
}

int bstr_begins_with_mem(const bstr *haystack, const void *_data, size_t len) {
    const unsigned char *data = (unsigned char *) _data;
    const unsigned char *hdata = bstr_ptr(haystack);
    size_t hlen = bstr_len(haystack);
    size_t pos = 0;

    while ((pos < len) && (pos < hlen)) {
        if (hdata[pos] != data[pos]) {
            return 0;
        }

        pos++;
    }

    if (pos == len) {
        return 1;
    } else {
        return 0;
    }
}

int bstr_begins_with_mem_nocase(const bstr *haystack, const void *_data, size_t len) {
    const unsigned char *data = (const unsigned char *) _data;
    const unsigned char *hdata = bstr_ptr(haystack);
    size_t hlen = bstr_len(haystack);
    size_t pos = 0;

    while ((pos < len) && (pos < hlen)) {
        if (tolower((int) hdata[pos]) != tolower((int) data[pos])) {
            return 0;
        }

        pos++;
    }

    if (pos == len) {
        return 1;
    } else {
        return 0;
    }
}

int bstr_char_at(const bstr *b, size_t pos) {
    unsigned char *data = bstr_ptr(b);
    size_t len = bstr_len(b);

    if (pos >= len) return -1;
    return data[pos];
}

int bstr_char_at_end(const bstr *b, size_t pos) {
    unsigned char *data = bstr_ptr(b);
    size_t len = bstr_len(b);

    if (pos >= len) return -1;
    return data[len - 1 - pos];
}

void bstr_chop(bstr *b) {
    if (bstr_len(b) > 0) {
        bstr_adjust_len(b, bstr_len(b) - 1);
    }
}

int bstr_chr(const bstr *b, int c) {
    unsigned char *data = bstr_ptr(b);
    size_t len = bstr_len(b);

    size_t i = 0;
    while (i < len) {
        if (data[i] == c) {
            return i;
        }

        i++;
    }

    return -1;
}

int bstr_cmp(const bstr *b1, const bstr *b2) {
    return bstr_util_cmp_mem(bstr_ptr(b1), bstr_len(b1), bstr_ptr(b2), bstr_len(b2));
}

int bstr_cmp_c(const bstr *b, const char *c) {
    return bstr_util_cmp_mem(bstr_ptr(b), bstr_len(b), c, strlen(c));
}

int bstr_cmp_c_nocase(const bstr *b, const char *c) {
    return bstr_util_cmp_mem_nocase(bstr_ptr(b), bstr_len(b), c, strlen(c));
}

int bstr_cmp_mem(const bstr *b, const void *data, size_t len) {
    return bstr_util_cmp_mem(bstr_ptr(b), bstr_len(b), data, len);
}

int bstr_cmp_mem_nocase(const bstr *b, const void *data, size_t len) {
    return bstr_util_cmp_mem_nocase(bstr_ptr(b), bstr_len(b), data, len);
}

int bstr_cmp_nocase(const bstr *b1, const bstr *b2) {
    return bstr_util_cmp_mem_nocase(bstr_ptr(b1), bstr_len(b1), bstr_ptr(b2), bstr_len(b2));
}

bstr *bstr_dup(const bstr *b) {
    return bstr_dup_ex(b, 0, bstr_len(b));
}

bstr *bstr_dup_c(const char *cstr) {
    return bstr_dup_mem(cstr, strlen(cstr));
}

bstr *bstr_dup_ex(const bstr *b, size_t offset, size_t len) {
    bstr *bnew = bstr_alloc(len);
    if (bnew == NULL) return NULL;
    memcpy(bstr_ptr(bnew), bstr_ptr(b) + offset, len);
    bstr_adjust_len(bnew, len);
    return bnew;
}

bstr *bstr_dup_lower(const bstr *b) {
    return bstr_to_lowercase(bstr_dup(b));
}

bstr *bstr_dup_mem(const void *data, size_t len) {
    bstr *bnew = bstr_alloc(len);
    if (bnew == NULL) return NULL;
    memcpy(bstr_ptr(bnew), data, len);
    bstr_adjust_len(bnew, len);
    return bnew;
}

bstr *bstr_expand(bstr *b, size_t newsize) {
    if (bstr_realptr(b) != NULL) {
        // Refuse to expand a wrapped bstring. In the future,
        // we can change this to make a copy of the data, thus
        // leaving the original memory area intact.
        return NULL;
    }

    // Catch attempts to "expand" to a smaller size
    if (bstr_size(b) > newsize) return NULL;

    bstr *bnew = realloc(b, sizeof (bstr) + newsize);
    if (bnew == NULL) return NULL;

    bstr_adjust_size(bnew, newsize);

    return bnew;
}

void bstr_free(bstr *b) {
    if (b == NULL) return;
    free(b);
}

int bstr_index_of(const bstr *haystack, const bstr *needle) {
    return bstr_index_of_mem(haystack, bstr_ptr(needle), bstr_len(needle));
}

int bstr_index_of_c(const bstr *haystack, const char *needle) {
    return bstr_index_of_mem(haystack, needle, strlen(needle));
}

int bstr_index_of_c_nocase(const bstr *haystack, const char *needle) {
    return bstr_index_of_mem_nocase(haystack, needle, strlen(needle));
}

int bstr_index_of_mem(const bstr *haystack, const void *_data2, size_t len2) {
    return bstr_util_mem_index_of_mem(bstr_ptr(haystack), bstr_len(haystack), _data2, len2);
}

int bstr_index_of_mem_nocase(const bstr *haystack, const void *_data2, size_t len2) {
    return bstr_util_mem_index_of_mem_nocase(bstr_ptr(haystack), bstr_len(haystack), _data2, len2);
}

int bstr_index_of_nocase(const bstr *haystack, const bstr *needle) {
    return bstr_index_of_mem_nocase(haystack, bstr_ptr(needle), bstr_len(needle));
}

int bstr_rchr(const bstr *b, int c) {
    const unsigned char *data = bstr_ptr(b);
    size_t len = bstr_len(b);

    size_t i = len;
    while (i > 0) {
        if (data[i - 1] == c) {
            return i - 1;
        }

        i--;
    }

    return -1;
}

bstr *bstr_to_lowercase(bstr *b) {
    if (b == NULL) return NULL;

    unsigned char *data = bstr_ptr(b);
    size_t len = bstr_len(b);

    size_t i = 0;
    while (i < len) {
        data[i] = tolower(data[i]);
        i++;
    }

    return b;
}

int bstr_util_cmp_mem(const void *_data1, size_t len1, const void *_data2, size_t len2) {
    const unsigned char *data1 = (const unsigned char *) _data1;
    const unsigned char *data2 = (const unsigned char *) _data2;
    size_t p1 = 0, p2 = 0;

    while ((p1 < len1) && (p2 < len2)) {
        if (data1[p1] != data2[p2]) {
            // Difference.
            return (data1[p1] < data2[p2]) ? -1 : 1;
        }

        p1++;
        p2++;
    }

    if ((p1 == len2) && (p2 == len1)) {
        // They're identical.
        return 0;
    } else {
        // One string is shorter.
        if (p1 == len1) return -1;
        else return 1;
    }
}

int bstr_util_cmp_mem_nocase(const void *_data1, size_t len1, const void *_data2, size_t len2) {
    const unsigned char *data1 = (const unsigned char *) _data1;
    const unsigned char *data2 = (const unsigned char *) _data2;
    size_t p1 = 0, p2 = 0;

    while ((p1 < len1) && (p2 < len2)) {
        if (tolower(data1[p1]) != tolower(data2[p2])) {
            // Difference.
            return (tolower(data1[p1]) < tolower(data2[p2])) ? -1 : 1;
        }

        p1++;
        p2++;
    }

    if ((p1 == len2) && (p2 == len1)) {
        // They're identical.
        return 0;
    } else {
        // One string is shorter.
        if (p1 == len1) return -1;
        else return 1;
    }
}

int64_t bstr_util_mem_to_pint(const void *_data, size_t len, int base, size_t *lastlen) {
    const unsigned char *data = (unsigned char *) _data;
    int64_t rval = 0, tflag = 0;
    size_t i = 0;

    *lastlen = i;

    for (i = 0; i < len; i++) {
        int d = data[i];

        *lastlen = i;

        // Convert character to digit.
        if ((d >= '0') && (d <= '9')) {
            d -= '0';
        } else if ((d >= 'a') && (d <= 'z')) {
            d -= 'a' - 10;
        } else if ((d >= 'A') && (d <= 'Z')) {
            d -= 'A' - 10;
        } else {
            d = -1;
        }

        // Check that the digit makes sense with the base we are using.
        if ((d == -1) || (d >= base)) {
            if (tflag) {
                // Return what we have so far; lastlen points
                // to the first non-digit position.
                return rval;
            } else {
                // We didn't see a single digit.
                return -1;
            }
        }

        if (tflag) {
            if (((INT64_MAX - d) / base) < rval) {
                // Overflow
                return -2;
            }

            rval *= base;
            rval += d;
        } else {
            rval = d;
            tflag = 1;
        }
    }

    *lastlen = i + 1;

    return rval;
}

int bstr_util_mem_index_of_c(const void *_data1, size_t len1, const char *cstr) {
    return bstr_util_mem_index_of_mem(_data1, len1, cstr, strlen(cstr));
}

int bstr_util_mem_index_of_c_nocase(const void *_data1, size_t len1, const char *cstr) {
    return bstr_util_mem_index_of_mem_nocase(_data1, len1, cstr, strlen(cstr));
}

int bstr_util_mem_index_of_mem(const void *_data1, size_t len1, const void *_data2, size_t len2) {
    const unsigned char *data1 = (unsigned char *) _data1;
    const unsigned char *data2 = (unsigned char *) _data2;
    size_t i, j;

    // If we ever want to optimize this function, the following link
    // might be useful: http://en.wikipedia.org/wiki/Knuth-Morris-Pratt_algorithm

    for (i = 0; i < len1; i++) {
        size_t k = i;

        for (j = 0; ((j < len2) && (k < len1)); j++, k++) {
            if (data1[k] != data2[j]) break;
        }

        if (j == len2) {
            return i;
        }
    }

    return -1;
}

int bstr_util_mem_index_of_mem_nocase(const void *_data1, size_t len1, const void *_data2, size_t len2) {
    const unsigned char *data1 = (unsigned char *) _data1;
    const unsigned char *data2 = (unsigned char *) _data2;
    size_t i, j;

    // If we ever want to optimize this function, the following link
    // might be useful: http://en.wikipedia.org/wiki/Knuth-Morris-Pratt_algorithm

    for (i = 0; i < len1; i++) {
        size_t k = i;

        for (j = 0; ((j < len2) && (k < len1)); j++, k++) {
            if (toupper(data1[k]) != toupper(data2[j])) break;
        }

        if (j == len2) {
            return i;
        }
    }

    return -1;
}

void bstr_util_mem_trim(unsigned char **data, size_t *len) {
    if ((data == NULL)||(len == NULL)) return;

    unsigned char *d = *data;
    size_t l = *len;

    // Ignore whitespace at the beginning.
    size_t pos = 0;
    while ((pos < l) && isspace(d[pos])) pos++;
    d += pos;
    l -= pos;

    // Ignore whitespace at the end.
    while ((l > 0)&&(isspace(d[l - 1]))) l--;

    *data = d;
    *len = l;
}

char *bstr_util_memdup_to_c(const void *_data, size_t len) {
    const unsigned char *data = (unsigned char *) _data;

    // Count how many NUL bytes we have in the string.
    size_t i, nulls = 0;
    for (i = 0; i < len; i++) {
        if (data[i] == '\0') {
            nulls++;
        }
    }

    // Now copy the string into a NUL-terminated buffer.

    char *r, *d;
    r = d = malloc(len + nulls + 1);
    if (d == NULL) return NULL;

    while (len--) {
        if (*data == '\0') {
            data++;
            *d++ = '\\';
            *d++ = '0';
        } else {
            *d++ = *data++;
        }
    }

    *d = '\0';

    return r;
}

char *bstr_util_strdup_to_c(const bstr *b) {
    if (b == NULL) return NULL;
    return bstr_util_memdup_to_c(bstr_ptr(b), bstr_len(b));
}

bstr *bstr_wrap_c(const char *cstr) {
    return bstr_wrap_mem((unsigned char *) cstr, strlen(cstr));
}

bstr *bstr_wrap_mem(const void *data, size_t len) {
    bstr *b = (bstr *) malloc(sizeof (bstr));
    if (b == NULL) return NULL;

    b->size = b->len = len;
    b->realptr = (unsigned char *) data;

    return b;
}
