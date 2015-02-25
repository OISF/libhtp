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

htp_hook_t *htp_hook_copy(const htp_hook_t *hook) {
    if (hook == NULL) return NULL;

    htp_hook_t *copy = htp_hook_create();
    if (copy == NULL) return NULL;

    for (size_t i = 0, n = htp_list_size(hook->callbacks); i < n; i++) {
        htp_callback_t *callback = htp_list_get(hook->callbacks, i);
        if (htp_hook_register(&copy, callback->fn) != HTP_OK) {
            htp_hook_destroy(copy);
            return NULL;
        }
    }

    return copy;
}

htp_hook_t *htp_hook_create(void) {
    htp_hook_t *hook = calloc(1, sizeof (htp_hook_t));
    if (hook == NULL) return NULL;

    hook->callbacks = (htp_list_array_t *) htp_list_array_create(4);
    if (hook->callbacks == NULL) {
        free(hook);
        return NULL;
    }

    return hook;
}

void htp_hook_destroy(htp_hook_t *hook) {
    if (hook == NULL) return;

    for (size_t i = 0, n = htp_list_size(hook->callbacks); i < n; i++) {
        free((htp_callback_t *) htp_list_get(hook->callbacks, i));
    }

    htp_list_array_destroy(hook->callbacks);

    free(hook);
}

htp_status_t htp_hook_register(htp_hook_t **hook, const htp_callback_fn_t callback_fn) {
    if (hook == NULL) return HTP_ERROR;

    htp_callback_t *callback = calloc(1, sizeof (htp_callback_t));
    if (callback == NULL) return HTP_ERROR;

    callback->fn = callback_fn;

    // Create a new hook if one does not exist
    int hook_created = 0;

    if (*hook == NULL) {
        hook_created = 1;

        *hook = htp_hook_create();
        if (*hook == NULL) {
            free(callback);
            return HTP_ERROR;
        }
    }

    // Add callback 
    if (htp_list_array_push((*hook)->callbacks, callback) != HTP_OK) {
        if (hook_created) {
            free(*hook);
        }

        free(callback);

        return HTP_ERROR;
    }

    return HTP_OK;
}

htp_status_t htp_hook_run_all(htp_hook_t *hook, void *user_data) {
    if (hook == NULL) return HTP_OK;

    // Loop through the registered callbacks, giving each a chance to run.
    for (size_t i = 0, n = htp_list_size(hook->callbacks); i < n; i++) {
        htp_callback_t *callback = htp_list_get(hook->callbacks, i);

        htp_status_t rc = callback->fn(user_data);

        // A hook can return HTP_OK to say that it did some work,
        // or HTP_DECLINED to say that it did no work. Anything else
        // is treated as an error.
        if ((rc != HTP_OK) && (rc != HTP_DECLINED)) {
            return rc;
        }
    }

    return HTP_OK;
}

htp_status_t htp_hook_run_one(htp_hook_t *hook, void *user_data) {
    if (hook == NULL) return HTP_DECLINED;

    for (size_t i = 0, n = htp_list_size(hook->callbacks); i < n; i++) {
        htp_callback_t *callback = htp_list_get(hook->callbacks, i);

        htp_status_t rc = callback->fn(user_data);

        // A hook can return HTP_DECLINED to say that it did no work,
        // and we'll ignore that. If we see HTP_OK or anything else,
        // we stop processing (because it was either a successful
        // handling or an error).
        if (rc != HTP_DECLINED) {
            // Return HTP_OK or an error.
            return rc;
        }
    }

    // No hook wanted to process the callback.
    return HTP_DECLINED;
}
