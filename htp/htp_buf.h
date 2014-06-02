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

#ifndef HTP_BUF_H
#define	HTP_BUF_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <htp.h>
#include <stdlib.h>

#define HTP_BUF_CHUNK_LIST_SIZE 4

typedef struct htp_buf_t {    
    htp_list_t     *chunks;    
    size_t          first_chunk_offset;
    
    unsigned char  *ext_data;
    size_t          ext_len;
    int             ext_read;

    size_t          current_chunk_index;
    size_t          current_offset;
} htp_buf_t;


htp_status_t htp_buf_add(htp_buf_t *b, void *data, size_t len);

htp_buf_t *htp_buf_create(void);

void htp_buf_destroy(htp_buf_t *b);

htp_status_t htp_buf_get(htp_buf_t *b, unsigned char **data, size_t *len);

htp_status_t htp_buf_keep(htp_buf_t *b);


#ifdef	__cplusplus
}
#endif

#endif	/* HTP_BUF_H */

