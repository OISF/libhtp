
#line 1 "htp_http_parsers.rl"
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

    
#line 61 "htp_http_parsers.c"
static const char _http_parser_content_range_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	3
};

static const char _http_parser_content_range_key_offsets[] = {
	0, 0, 1, 2, 3, 4, 5, 6, 
	9, 10, 13, 16, 18, 21, 21
};

static const char _http_parser_content_range_trans_keys[] = {
	98, 121, 116, 101, 115, 32, 42, 48, 
	57, 47, 42, 48, 57, 45, 48, 57, 
	48, 57, 47, 48, 57, 48, 57, 0
};

static const char _http_parser_content_range_single_lengths[] = {
	0, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 0, 1, 0, 0
};

static const char _http_parser_content_range_range_lengths[] = {
	0, 0, 0, 0, 0, 0, 0, 1, 
	0, 1, 1, 1, 1, 0, 1
};

static const char _http_parser_content_range_index_offsets[] = {
	0, 0, 2, 4, 6, 8, 10, 12, 
	15, 17, 20, 23, 25, 28, 29
};

static const char _http_parser_content_range_trans_targs[] = {
	2, 0, 3, 0, 4, 0, 5, 0, 
	6, 0, 7, 0, 8, 10, 0, 9, 
	0, 13, 14, 0, 11, 10, 0, 12, 
	0, 9, 12, 0, 0, 14, 0, 0
};

static const char _http_parser_content_range_trans_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 0, 0, 
	0, 0, 1, 0, 3, 0, 0, 1, 
	0, 5, 0, 0, 0, 0, 0, 0
};

static const char _http_parser_content_range_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 7
};

static const int http_parser_content_range_start = 1;
static const int http_parser_content_range_error = 0;

static const int http_parser_content_range_en_main = 1;


#line 118 "htp_http_parsers.c"
	{
	cs = http_parser_content_range_start;
	}

#line 123 "htp_http_parsers.c"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _http_parser_content_range_trans_keys + _http_parser_content_range_key_offsets[cs];
	_trans = _http_parser_content_range_index_offsets[cs];

	_klen = _http_parser_content_range_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _http_parser_content_range_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	cs = _http_parser_content_range_trans_targs[_trans];

	if ( _http_parser_content_range_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _http_parser_content_range_actions + _http_parser_content_range_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 62 "htp_http_parsers.rl"
	{
            mark = p;
        }
	break;
	case 1:
#line 66 "htp_http_parsers.rl"
	{
            p_first_byte_pos = bstr_util_mem_to_pint(mark, p - mark, 10, NULL);
            if (p_first_byte_pos < -1) p_first_byte_pos = -1;
        }
	break;
	case 2:
#line 71 "htp_http_parsers.rl"
	{
            p_last_byte_pos = bstr_util_mem_to_pint(mark, p - mark, 10, NULL);
            if (p_last_byte_pos < -1) p_last_byte_pos = -1;
        }
	break;
#line 216 "htp_http_parsers.c"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	const char *__acts = _http_parser_content_range_actions + _http_parser_content_range_eof_actions[cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 3:
#line 76 "htp_http_parsers.rl"
	{
            p_instance_length = bstr_util_mem_to_pint(mark, p - mark, 10, NULL);
            if (p_instance_length < -1) p_last_byte_pos = -1;
        }
	break;
#line 239 "htp_http_parsers.c"
		}
	}
	}

	_out: {}
	}

#line 100 "htp_http_parsers.rl"


    if (cs == http_parser_content_range_error) return HTP_ERROR;

    // Temporary workaround to avoid the unused variable error.
    cs = http_parser_content_range_en_main;

    *first_byte_pos = p_first_byte_pos;
    *last_byte_pos = p_last_byte_pos;
    *instance_length = p_instance_length;

    return HTP_OK;
}
