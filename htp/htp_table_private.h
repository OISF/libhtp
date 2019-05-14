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

#ifndef HTP_TABLE_PRIVATE_H
#define	HTP_TABLE_PRIVATE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "htp_list.h"
#include "htp_table.h"

enum htp_table_alloc_t {
    /** This is the default value, used only until the first element is added. */
    HTP_TABLE_KEYS_ALLOC_UKNOWN = 0,

    /** Keys are copied.*/
    HTP_TABLE_KEYS_COPIED = 1,

    /** Keys are adopted and freed when the table is destroyed. */
    HTP_TABLE_KEYS_ADOPTED = 2,

    /** Keys are only referenced; the caller is still responsible for freeing them after the table is destroyed. */
    HTP_TABLE_KEYS_REFERENCED = 3
};

struct htp_table_t {
    /** Table key and value pairs are stored in this list; name first, then value. */
    htp_list_t list;

    /**
     * Key management strategy. Initially set to HTP_TABLE_KEYS_ALLOC_UKNOWN. The
     * actual strategy is determined by the first allocation.
     */
    enum htp_table_alloc_t alloc_type;
};

#ifdef	__cplusplus
}
#endif

#endif	/* HTP_TABLE_PRIVATE_H */
