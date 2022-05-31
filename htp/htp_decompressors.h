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

#ifndef _HTP_DECOMPRESSORS_H
#define	_HTP_DECOMPRESSORS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <zlib.h>
#include "lzma/LzmaDec.h"

typedef struct htp_decompressor_gzip_t htp_decompressor_gzip_t;
typedef struct htp_decompressor_t htp_decompressor_t;

#define GZIP_BUF_SIZE           8192

#define DEFLATE_MAGIC_1         0x1f
#define DEFLATE_MAGIC_2         0x8b

struct htp_decompressor_t {
    // no longer used
    htp_status_t (*decompress)(htp_decompressor_t *, htp_tx_data_t *);
    htp_status_t (*callback)(htp_tx_data_t *);
    // no longer used
    void (*destroy)(htp_decompressor_t *);
    struct htp_decompressor_t *next;
    struct timeval time_before;
    int32_t time_spent;
    uint32_t nb_callbacks;
    uint8_t passthrough;    /**< decompression failed, pass through raw data */
};

struct htp_decompressor_gzip_t {
    htp_decompressor_t super;
    #if 0
    int initialized;
    #endif
    int zlib_initialized;
    uint8_t restart;    /**< deflate restarted to try rfc1950 instead of 1951 */
    z_stream stream;
    uint8_t header[LZMA_PROPS_SIZE + 8];
    uint8_t header_len;
    CLzmaDec state;
    unsigned char *buffer;
    unsigned long crc;    
};

htp_decompressor_t *htp_gzip_decompressor_create(htp_connp_t *connp, enum htp_content_encoding_t format);
htp_status_t htp_gzip_decompressor_decompress(htp_decompressor_t *drec, htp_tx_data_t *d);
void htp_gzip_decompressor_destroy(htp_decompressor_t *drec);

#ifdef __cplusplus
}
#endif

#endif	/* _HTP_DECOMPRESSORS_H */

