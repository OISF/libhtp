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

/**
 * This is a proof-of-concept processor that processes parameter names in
 * a way _similar_ to PHP. Whitespace at the beginning is removed, and the
 * remaining whitespace characters are converted to underscores. Proper
 * research of PHP's behavior is needed before we can claim to be emulating it.
 *
 * @param[in,out] p
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_php_parameter_processor(htp_param_t *p) {
    if (p == NULL) return HTP_ERROR;

    // Name transformation

    bstr *new_name = NULL;

    // Ignore whitespace characters at the beginning of parameter name.

    unsigned char *data = bstr_ptr(p->name);
    size_t len = bstr_len(p->name);
    size_t pos = 0;

    // Advance over any whitespace characters at the beginning of the name.
    while ((pos < len) && (isspace(data[pos]))) pos++;

    // Have we seen any whitespace?
    if (pos > 0) {
        // Make a copy of the name, starting with
        // the first non-whitespace character.
        new_name = bstr_dup_mem(data + pos, len - pos);
        if (new_name == NULL) return HTP_ERROR;
    }
    
    // Replace remaining whitespace characters with underscores.

    size_t offset = pos;
    pos = 0;
    
    // Advance to the end of name or to the first whitespace character.
    while ((offset + pos < len)&&(!isspace(data[pos]))) pos++;

    // Are we at the end of the name?
    if (offset + pos < len) {
        // Seen whitespace within the string.

        // Make a copy of the name if needed (which would be the case
        // with a parameter that does not have any whitespace in front).
        if (new_name == NULL) {
            new_name = bstr_dup(p->name);
            if (new_name == NULL) return HTP_ERROR;
        }
        
        // Change the pointers to the new name and ditch the offset.
        data = bstr_ptr(new_name);
        len = bstr_len(new_name);

        // Replace any whitespace characters in the copy with underscores.
        while (pos < len) {
            if (isspace(data[pos])) {
                data[pos] = '_';
            }
        
            pos++;
        }
    }

    // If we made any changes, free the old parameter name and put the new one in.
    if (new_name != NULL) {
        bstr_free(p->name);
        p->name = new_name;
    }

    return HTP_OK;
}
