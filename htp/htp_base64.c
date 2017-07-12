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

/* Adapted from the libb64 project (http://sourceforge.net/projects/libb64), which is in public domain. */

#include "bstr.h"
#include "htp_base64.h"

/**
 * Decode single base64-encoded character.
 *
 * @param[in] value_in
 * @return decoded character
 */
int htp_base64_decode_single(signed char value_in) {
    static const signed char decoding[] = {62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
        -1, -1, -1, -2, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};
    static const signed char decoding_size = sizeof (decoding);

    value_in -= 43;

    if ((value_in < 0) || (value_in > decoding_size - 1)) return -1;

    return decoding[(int) value_in];
}

/**
 * Initialize base64 decoder.
 *
 * @param[in] decoder
 */
void htp_base64_decoder_init(htp_base64_decoder *decoder) {
    decoder->step = step_a;
    decoder->plainchar = 0;
}

/**
 * Feed the supplied memory range to the decoder.
 *
 * @param[in] decoder
 * @param[in] _code_in
 * @param[in] length_in
 * @param[in] _plaintext_out
 * @param[in] length_out
 * @return how many bytes were placed into plaintext output
 */
int htp_base64_decode(htp_base64_decoder *decoder, const void *_code_in, int length_in, void *_plaintext_out, int length_out) {
    const unsigned char *code_in = (const unsigned char *)_code_in;
    unsigned char *plaintext_out = (unsigned char *)_plaintext_out;
    const unsigned char *codechar = code_in;
    unsigned char *plainchar = plaintext_out;
    signed char fragment;

    if (length_out <= 0) return 0;

    *plainchar = decoder->plainchar;

    switch (decoder->step) {
            while (1) {
                case step_a:
                do {
                    if (codechar == code_in + length_in) {
                        decoder->step = step_a;
                        decoder->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char) htp_base64_decode_single(*codechar++);
                } while (fragment < 0);
                *plainchar = (fragment & 0x03f) << 2;
                /* fall through */

                case step_b:
                do {
                    if (codechar == code_in + length_in) {
                        decoder->step = step_b;
                        decoder->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char) htp_base64_decode_single(*codechar++);
                } while (fragment < 0);
                *plainchar++ |= (fragment & 0x030) >> 4;
                *plainchar = (fragment & 0x00f) << 4;                
                if (--length_out == 0) {
                    return plainchar - plaintext_out;
                }
                /* fall through */

                case step_c:
                do {
                    if (codechar == code_in + length_in) {
                        decoder->step = step_c;
                        decoder->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char) htp_base64_decode_single(*codechar++);
                } while (fragment < 0);
                *plainchar++ |= (fragment & 0x03c) >> 2;
                *plainchar = (fragment & 0x003) << 6;
                if (--length_out == 0) {
                    return plainchar - plaintext_out;
                }
                /* fall through */

                case step_d:
                do {
                    if (codechar == code_in + length_in) {
                        decoder->step = step_d;
                        decoder->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char) htp_base64_decode_single(*codechar++);
                } while (fragment < 0);
                *plainchar++ |= (fragment & 0x03f);
                if (--length_out == 0) {
                    return plainchar - plaintext_out;
                }
                /* fall through */
            }
    }

    /* control should not reach here */
    return plainchar - plaintext_out;
}

/**
 * Base64-decode input, given as bstring.
 *
 * @param[in] input
 * @return new base64-decoded bstring
 */
bstr *htp_base64_decode_bstr(bstr *input) {
    return htp_base64_decode_mem(bstr_ptr(input), bstr_len(input));
}

/**
 * Base64-decode input, given as memory range.
 *
 * @param[in] data
 * @param[in] len
 * @return new base64-decoded bstring
 */
bstr *htp_base64_decode_mem(const void *data, size_t len) {
    htp_base64_decoder decoder;
    bstr *r = NULL;

    htp_base64_decoder_init(&decoder);

    unsigned char *tmpstr = malloc(len);
    if (tmpstr == NULL) return NULL;

    int resulting_len = htp_base64_decode(&decoder, data, len, tmpstr, len);
    if (resulting_len > 0) {
        r = bstr_dup_mem(tmpstr, resulting_len);
    }

    free(tmpstr);

    return r;
}
