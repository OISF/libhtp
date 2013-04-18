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

#ifndef _HOOKS_H
#define	_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct htp_hook_t htp_hook_t;
typedef struct htp_callback_t htp_callback_t;
typedef int (*htp_callback_fn_t) (void *);

#include "htp.h"

struct htp_hook_t {
    htp_list_array_t *callbacks;
};

struct htp_callback_t {
    htp_callback_fn_t fn;
};

/**
 * Creates a copy of the provided hook. The hook is allowed to be NULL,
 * in which case this function simply returns a NULL.
 *
 * @param[in] hook
 * @return A copy of the hook, or NULL (if the provided hook was NULL
 *         or, if it wasn't, if there was a memory allocation problem while
 *         constructing a copy).
 */
htp_hook_t *htp_hook_copy(const htp_hook_t *hook);

/**
 * Creates a new hook.
 *
 * @return New htp_hook_t structure on success, NULL on failure.
 */
htp_hook_t *htp_hook_create(void);

/**
 * Destroys an existing hook. It is all right to send a NULL
 * to this method because it will simply return straight away.
 *
 * @param[in] hook
 */
void htp_hook_destroy(htp_hook_t *hook);

/**
 * Registers a new callback with the hook.
 *
 * @param[in] hook
 * @param[in] callback_fn
 * @return HTP_OK on success, HTP_ERROR on memory allocation error.
 */
htp_status_t htp_hook_register(htp_hook_t **hook, const htp_callback_fn_t callback_fn);

/**
 * Runs all the callbacks associated with a given hook. Only stops if
 * one of the callbacks returns an error (HTP_ERROR) or stop (HTP_STOP).
 *
 * @param[in] hook
 * @param[in] user_data
 * @return HTP_OK if at least one hook ran successfully, HTP_STOP if there was
 *         no error but processing should stop, and HTP_ERROR or any other value
 *         less than zero on error.
 */
htp_status_t htp_hook_run_all(htp_hook_t *hook, void *user_data);

/**
 * Run callbacks one by one until one of them accepts to service the hook.
 *
 * @param[in] hook
 * @param[in] user_data
 * @return HTP_OK if a hook was found to process the callback, HTP_DECLINED if
 *         no hook could be found, HTP_STOP if a hook signalled the processing
 *         to stop, and HTP_ERROR or any other value less than zero on error.
 */
htp_status_t htp_hook_run_one(htp_hook_t *hook, void *user_data);

#ifdef __cplusplus
}
#endif

#endif	/* _HOOKS_H */
