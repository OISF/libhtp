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

#include "htp_http_parsers.h"

htp_status_t htp_parse_content_range(void *data, size_t len, int64_t *first_byte_pos, int64_t *last_byte_pos,
        int64_t *instance_length)
{
    if ((data == NULL)||(first_byte_pos == NULL)
        ||(last_byte_pos == NULL)||(instance_length == NULL)) return HTP_ERROR;

    int cs;
    char *p = (char *)data;
    char *pe = p + len;
    char *eof = pe;
    char *mark = NULL;

    int64_t p_first_byte_pos = -1;
    int64_t p_last_byte_pos = -1;
    int64_t p_instance_length = -1;

    %%{
        machine content_range;

        write data nofinal;

        action mark {
            mark = fpc;
        }

        action first_byte_pos {
            p_first_byte_pos = bstr_util_mem_to_pint(mark, fpc - mark, 10, NULL);
            if (p_first_byte_pos < -1) {
                fnext *content_range_error;
                fbreak;
            }
        }

        action last_byte_pos {
            p_last_byte_pos = bstr_util_mem_to_pint(mark, fpc - mark, 10, NULL);
            if (p_last_byte_pos < -1)  {
                fnext *content_range_error;
                fbreak;
            }
        }

        action instance_length {
            p_instance_length = bstr_util_mem_to_pint(mark, fpc - mark, 10, NULL);
            if (p_instance_length < -1)  {
                fnext *content_range_error;
                fbreak;
            }
        }

        SP = ' ';

        bytes_unit = 'bytes';

        instance_length = digit+ >mark %instance_length;

        first_byte_pos = digit+ >mark %first_byte_pos;

        last_byte_pos = digit+ >mark %last_byte_pos;

        byte_range_resp_spec = (first_byte_pos "-" last_byte_pos | "*" );

        content_range_spec = bytes_unit SP byte_range_resp_spec "/" ( instance_length | "*" );

        main := content_range_spec;

        write init;
        write exec;

    }%%

    if (cs < %%{ write first_final; }%%) return HTP_ERROR;

    // Temporary workaround to avoid the unused variable error.
    cs = content_range_en_main;

    *first_byte_pos = p_first_byte_pos;
    *last_byte_pos = p_last_byte_pos;
    *instance_length = p_instance_length;

    return HTP_OK;
}
