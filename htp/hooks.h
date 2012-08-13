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

#ifndef _HOOKS_H
#define	_HOOKS_H

#include "dslib.h"

#ifdef _HTP_H
#define HOOK_ERROR      HTP_ERROR
#define HOOK_OK         HTP_OK
#define HOOK_DECLINED   HTP_DECLINED
#define HOOK_STOP       HTP_STOP
#else
#define HOOK_ERROR      -1
#define HOOK_OK          0
#define HOOK_DECLINED    1
#define HOOK_STOP        4
#endif

typedef struct htp_hook_t htp_hook_t;
typedef struct htp_callback_t htp_callback_t;
typedef int (*htp_callback_fn_t) (void *);

#ifdef __cplusplus
extern "C" {
#endif

struct htp_hook_t {
    list_t *callbacks;
};

struct htp_callback_t {
    htp_callback_fn_t fn;
};

 int hook_register(htp_hook_t **hook, htp_callback_fn_t callback_fn);
 int hook_run_one(htp_hook_t *hook, void *data);
 int hook_run_all(htp_hook_t *hook, void *data);

htp_hook_t *hook_create(void);
htp_hook_t *hook_copy(htp_hook_t *hook);
       void hook_destroy(htp_hook_t *hook);


#ifdef __cplusplus
}
#endif

#endif	/* _HOOKS_H */

