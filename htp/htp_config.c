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
 * This map is used by default for best-fit mapping from the Unicode
 * values U+0100-FFFF.
 */
static unsigned char bestfit_1252[] = {
    0x01, 0x00, 0x41, 0x01, 0x01, 0x61, 0x01, 0x02, 0x41, 0x01, 0x03, 0x61,
    0x01, 0x04, 0x41, 0x01, 0x05, 0x61, 0x01, 0x06, 0x43, 0x01, 0x07, 0x63,
    0x01, 0x08, 0x43, 0x01, 0x09, 0x63, 0x01, 0x0a, 0x43, 0x01, 0x0b, 0x63,
    0x01, 0x0c, 0x43, 0x01, 0x0d, 0x63, 0x01, 0x0e, 0x44, 0x01, 0x0f, 0x64,
    0x01, 0x11, 0x64, 0x01, 0x12, 0x45, 0x01, 0x13, 0x65, 0x01, 0x14, 0x45,
    0x01, 0x15, 0x65, 0x01, 0x16, 0x45, 0x01, 0x17, 0x65, 0x01, 0x18, 0x45,
    0x01, 0x19, 0x65, 0x01, 0x1a, 0x45, 0x01, 0x1b, 0x65, 0x01, 0x1c, 0x47,
    0x01, 0x1d, 0x67, 0x01, 0x1e, 0x47, 0x01, 0x1f, 0x67, 0x01, 0x20, 0x47,
    0x01, 0x21, 0x67, 0x01, 0x22, 0x47, 0x01, 0x23, 0x67, 0x01, 0x24, 0x48,
    0x01, 0x25, 0x68, 0x01, 0x26, 0x48, 0x01, 0x27, 0x68, 0x01, 0x28, 0x49,
    0x01, 0x29, 0x69, 0x01, 0x2a, 0x49, 0x01, 0x2b, 0x69, 0x01, 0x2c, 0x49,
    0x01, 0x2d, 0x69, 0x01, 0x2e, 0x49, 0x01, 0x2f, 0x69, 0x01, 0x30, 0x49,
    0x01, 0x31, 0x69, 0x01, 0x34, 0x4a, 0x01, 0x35, 0x6a, 0x01, 0x36, 0x4b,
    0x01, 0x37, 0x6b, 0x01, 0x39, 0x4c, 0x01, 0x3a, 0x6c, 0x01, 0x3b, 0x4c,
    0x01, 0x3c, 0x6c, 0x01, 0x3d, 0x4c, 0x01, 0x3e, 0x6c, 0x01, 0x41, 0x4c,
    0x01, 0x42, 0x6c, 0x01, 0x43, 0x4e, 0x01, 0x44, 0x6e, 0x01, 0x45, 0x4e,
    0x01, 0x46, 0x6e, 0x01, 0x47, 0x4e, 0x01, 0x48, 0x6e, 0x01, 0x4c, 0x4f,
    0x01, 0x4d, 0x6f, 0x01, 0x4e, 0x4f, 0x01, 0x4f, 0x6f, 0x01, 0x50, 0x4f,
    0x01, 0x51, 0x6f, 0x01, 0x54, 0x52, 0x01, 0x55, 0x72, 0x01, 0x56, 0x52,
    0x01, 0x57, 0x72, 0x01, 0x58, 0x52, 0x01, 0x59, 0x72, 0x01, 0x5a, 0x53,
    0x01, 0x5b, 0x73, 0x01, 0x5c, 0x53, 0x01, 0x5d, 0x73, 0x01, 0x5e, 0x53,
    0x01, 0x5f, 0x73, 0x01, 0x62, 0x54, 0x01, 0x63, 0x74, 0x01, 0x64, 0x54,
    0x01, 0x65, 0x74, 0x01, 0x66, 0x54, 0x01, 0x67, 0x74, 0x01, 0x68, 0x55,
    0x01, 0x69, 0x75, 0x01, 0x6a, 0x55, 0x01, 0x6b, 0x75, 0x01, 0x6c, 0x55,
    0x01, 0x6d, 0x75, 0x01, 0x6e, 0x55, 0x01, 0x6f, 0x75, 0x01, 0x70, 0x55,
    0x01, 0x71, 0x75, 0x01, 0x72, 0x55, 0x01, 0x73, 0x75, 0x01, 0x74, 0x57,
    0x01, 0x75, 0x77, 0x01, 0x76, 0x59, 0x01, 0x77, 0x79, 0x01, 0x79, 0x5a,
    0x01, 0x7b, 0x5a, 0x01, 0x7c, 0x7a, 0x01, 0x80, 0x62, 0x01, 0x97, 0x49,
    0x01, 0x9a, 0x6c, 0x01, 0x9f, 0x4f, 0x01, 0xa0, 0x4f, 0x01, 0xa1, 0x6f,
    0x01, 0xab, 0x74, 0x01, 0xae, 0x54, 0x01, 0xaf, 0x55, 0x01, 0xb0, 0x75,
    0x01, 0xb6, 0x7a, 0x01, 0xc0, 0x7c, 0x01, 0xc3, 0x21, 0x01, 0xcd, 0x41,
    0x01, 0xce, 0x61, 0x01, 0xcf, 0x49, 0x01, 0xd0, 0x69, 0x01, 0xd1, 0x4f,
    0x01, 0xd2, 0x6f, 0x01, 0xd3, 0x55, 0x01, 0xd4, 0x75, 0x01, 0xd5, 0x55,
    0x01, 0xd6, 0x75, 0x01, 0xd7, 0x55, 0x01, 0xd8, 0x75, 0x01, 0xd9, 0x55,
    0x01, 0xda, 0x75, 0x01, 0xdb, 0x55, 0x01, 0xdc, 0x75, 0x01, 0xde, 0x41,
    0x01, 0xdf, 0x61, 0x01, 0xe4, 0x47, 0x01, 0xe5, 0x67, 0x01, 0xe6, 0x47,
    0x01, 0xe7, 0x67, 0x01, 0xe8, 0x4b, 0x01, 0xe9, 0x6b, 0x01, 0xea, 0x4f,
    0x01, 0xeb, 0x6f, 0x01, 0xec, 0x4f, 0x01, 0xed, 0x6f, 0x01, 0xf0, 0x6a,
    0x02, 0x61, 0x67, 0x02, 0xb9, 0x27, 0x02, 0xba, 0x22, 0x02, 0xbc, 0x27,
    0x02, 0xc4, 0x5e, 0x02, 0xc8, 0x27, 0x02, 0xcb, 0x60, 0x02, 0xcd, 0x5f,
    0x03, 0x00, 0x60, 0x03, 0x02, 0x5e, 0x03, 0x03, 0x7e, 0x03, 0x0e, 0x22,
    0x03, 0x31, 0x5f, 0x03, 0x32, 0x5f, 0x03, 0x7e, 0x3b, 0x03, 0x93, 0x47,
    0x03, 0x98, 0x54, 0x03, 0xa3, 0x53, 0x03, 0xa6, 0x46, 0x03, 0xa9, 0x4f,
    0x03, 0xb1, 0x61, 0x03, 0xb4, 0x64, 0x03, 0xb5, 0x65, 0x03, 0xc0, 0x70,
    0x03, 0xc3, 0x73, 0x03, 0xc4, 0x74, 0x03, 0xc6, 0x66, 0x04, 0xbb, 0x68,
    0x05, 0x89, 0x3a, 0x06, 0x6a, 0x25, 0x20, 0x00, 0x20, 0x20, 0x01, 0x20,
    0x20, 0x02, 0x20, 0x20, 0x03, 0x20, 0x20, 0x04, 0x20, 0x20, 0x05, 0x20,
    0x20, 0x06, 0x20, 0x20, 0x10, 0x2d, 0x20, 0x11, 0x2d, 0x20, 0x17, 0x3d,
    0x20, 0x32, 0x27, 0x20, 0x35, 0x60, 0x20, 0x44, 0x2f, 0x20, 0x74, 0x34,
    0x20, 0x75, 0x35, 0x20, 0x76, 0x36, 0x20, 0x77, 0x37, 0x20, 0x78, 0x38,
    0x20, 0x7f, 0x6e, 0x20, 0x80, 0x30, 0x20, 0x81, 0x31, 0x20, 0x82, 0x32,
    0x20, 0x83, 0x33, 0x20, 0x84, 0x34, 0x20, 0x85, 0x35, 0x20, 0x86, 0x36,
    0x20, 0x87, 0x37, 0x20, 0x88, 0x38, 0x20, 0x89, 0x39, 0x20, 0xa7, 0x50,
    0x21, 0x02, 0x43, 0x21, 0x07, 0x45, 0x21, 0x0a, 0x67, 0x21, 0x0b, 0x48,
    0x21, 0x0c, 0x48, 0x21, 0x0d, 0x48, 0x21, 0x0e, 0x68, 0x21, 0x10, 0x49,
    0x21, 0x11, 0x49, 0x21, 0x12, 0x4c, 0x21, 0x13, 0x6c, 0x21, 0x15, 0x4e,
    0x21, 0x18, 0x50, 0x21, 0x19, 0x50, 0x21, 0x1a, 0x51, 0x21, 0x1b, 0x52,
    0x21, 0x1c, 0x52, 0x21, 0x1d, 0x52, 0x21, 0x24, 0x5a, 0x21, 0x28, 0x5a,
    0x21, 0x2a, 0x4b, 0x21, 0x2c, 0x42, 0x21, 0x2d, 0x43, 0x21, 0x2e, 0x65,
    0x21, 0x2f, 0x65, 0x21, 0x30, 0x45, 0x21, 0x31, 0x46, 0x21, 0x33, 0x4d,
    0x21, 0x34, 0x6f, 0x22, 0x12, 0x2d, 0x22, 0x15, 0x2f, 0x22, 0x16, 0x5c,
    0x22, 0x17, 0x2a, 0x22, 0x1a, 0x76, 0x22, 0x1e, 0x38, 0x22, 0x23, 0x7c,
    0x22, 0x29, 0x6e, 0x22, 0x36, 0x3a, 0x22, 0x3c, 0x7e, 0x22, 0x61, 0x3d,
    0x22, 0x64, 0x3d, 0x22, 0x65, 0x3d, 0x23, 0x03, 0x5e, 0x23, 0x20, 0x28,
    0x23, 0x21, 0x29, 0x23, 0x29, 0x3c, 0x23, 0x2a, 0x3e, 0x25, 0x00, 0x2d,
    0x25, 0x0c, 0x2b, 0x25, 0x10, 0x2b, 0x25, 0x14, 0x2b, 0x25, 0x18, 0x2b,
    0x25, 0x1c, 0x2b, 0x25, 0x2c, 0x2d, 0x25, 0x34, 0x2d, 0x25, 0x3c, 0x2b,
    0x25, 0x50, 0x2d, 0x25, 0x52, 0x2b, 0x25, 0x53, 0x2b, 0x25, 0x54, 0x2b,
    0x25, 0x55, 0x2b, 0x25, 0x56, 0x2b, 0x25, 0x57, 0x2b, 0x25, 0x58, 0x2b,
    0x25, 0x59, 0x2b, 0x25, 0x5a, 0x2b, 0x25, 0x5b, 0x2b, 0x25, 0x5c, 0x2b,
    0x25, 0x5d, 0x2b, 0x25, 0x64, 0x2d, 0x25, 0x65, 0x2d, 0x25, 0x66, 0x2d,
    0x25, 0x67, 0x2d, 0x25, 0x68, 0x2d, 0x25, 0x69, 0x2d, 0x25, 0x6a, 0x2b,
    0x25, 0x6b, 0x2b, 0x25, 0x6c, 0x2b, 0x25, 0x84, 0x5f, 0x27, 0x58, 0x7c,
    0x30, 0x00, 0x20, 0x30, 0x08, 0x3c, 0x30, 0x09, 0x3e, 0x30, 0x1a, 0x5b,
    0x30, 0x1b, 0x5d, 0xff, 0x01, 0x21, 0xff, 0x02, 0x22, 0xff, 0x03, 0x23,
    0xff, 0x04, 0x24, 0xff, 0x05, 0x25, 0xff, 0x06, 0x26, 0xff, 0x07, 0x27,
    0xff, 0x08, 0x28, 0xff, 0x09, 0x29, 0xff, 0x0a, 0x2a, 0xff, 0x0b, 0x2b,
    0xff, 0x0c, 0x2c, 0xff, 0x0d, 0x2d, 0xff, 0x0e, 0x2e, 0xff, 0x0f, 0x2f,
    0xff, 0x10, 0x30, 0xff, 0x11, 0x31, 0xff, 0x12, 0x32, 0xff, 0x13, 0x33,
    0xff, 0x14, 0x34, 0xff, 0x15, 0x35, 0xff, 0x16, 0x36, 0xff, 0x17, 0x37,
    0xff, 0x18, 0x38, 0xff, 0x19, 0x39, 0xff, 0x1a, 0x3a, 0xff, 0x1b, 0x3b,
    0xff, 0x1c, 0x3c, 0xff, 0x1d, 0x3d, 0xff, 0x1e, 0x3e, 0xff, 0x20, 0x40,
    0xff, 0x21, 0x41, 0xff, 0x22, 0x42, 0xff, 0x23, 0x43, 0xff, 0x24, 0x44,
    0xff, 0x25, 0x45, 0xff, 0x26, 0x46, 0xff, 0x27, 0x47, 0xff, 0x28, 0x48,
    0xff, 0x29, 0x49, 0xff, 0x2a, 0x4a, 0xff, 0x2b, 0x4b, 0xff, 0x2c, 0x4c,
    0xff, 0x2d, 0x4d, 0xff, 0x2e, 0x4e, 0xff, 0x2f, 0x4f, 0xff, 0x30, 0x50,
    0xff, 0x31, 0x51, 0xff, 0x32, 0x52, 0xff, 0x33, 0x53, 0xff, 0x34, 0x54,
    0xff, 0x35, 0x55, 0xff, 0x36, 0x56, 0xff, 0x37, 0x57, 0xff, 0x38, 0x58,
    0xff, 0x39, 0x59, 0xff, 0x3a, 0x5a, 0xff, 0x3b, 0x5b, 0xff, 0x3c, 0x5c,
    0xff, 0x3d, 0x5d, 0xff, 0x3e, 0x5e, 0xff, 0x3f, 0x5f, 0xff, 0x40, 0x60,
    0xff, 0x41, 0x61, 0xff, 0x42, 0x62, 0xff, 0x43, 0x63, 0xff, 0x44, 0x64,
    0xff, 0x45, 0x65, 0xff, 0x46, 0x66, 0xff, 0x47, 0x67, 0xff, 0x48, 0x68,
    0xff, 0x49, 0x69, 0xff, 0x4a, 0x6a, 0xff, 0x4b, 0x6b, 0xff, 0x4c, 0x6c,
    0xff, 0x4d, 0x6d, 0xff, 0x4e, 0x6e, 0xff, 0x4f, 0x6f, 0xff, 0x50, 0x70,
    0xff, 0x51, 0x71, 0xff, 0x52, 0x72, 0xff, 0x53, 0x73, 0xff, 0x54, 0x74,
    0xff, 0x55, 0x75, 0xff, 0x56, 0x76, 0xff, 0x57, 0x77, 0xff, 0x58, 0x78,
    0xff, 0x59, 0x79, 0xff, 0x5a, 0x7a, 0xff, 0x5b, 0x7b, 0xff, 0x5c, 0x7c,
    0xff, 0x5d, 0x7d, 0xff, 0x5e, 0x7e, 0x00, 0x00, 0x00
};

htp_cfg_t *htp_config_create(void) {
    htp_cfg_t *cfg = calloc(1, sizeof (htp_cfg_t));
    if (cfg == NULL) return NULL;

    cfg->field_limit_hard = HTP_FIELD_LIMIT_HARD;
    cfg->field_limit_soft = HTP_FIELD_LIMIT_SOFT;
    cfg->log_level = HTP_LOG_NOTICE;
    cfg->response_decompression_enabled = 1;
    cfg->parse_request_cookies = 1;
    cfg->parse_request_auth = 1;
    cfg->extract_request_files = 0;
    cfg->extract_request_files_limit = -1; // Use the parser default.
    cfg->response_decompression_layer_limit = 2; // 2 layers seem fairly common

    // Default settings for URL-encoded data.

    htp_config_set_bestfit_map(cfg, HTP_DECODER_DEFAULTS, bestfit_1252);
    htp_config_set_bestfit_replacement_byte(cfg, HTP_DECODER_DEFAULTS, '?');

    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_config_set_nul_raw_terminates(cfg, HTP_DECODER_DEFAULTS, 0);
    htp_config_set_nul_encoded_terminates(cfg, HTP_DECODER_DEFAULTS, 0);
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 0);

    htp_config_set_plusspace_decode(cfg, HTP_DECODER_URLENCODED, 1);

    htp_config_set_server_personality(cfg, HTP_SERVER_MINIMAL);

    return cfg;
}

htp_cfg_t *htp_config_copy(htp_cfg_t *cfg) {
    if (cfg == NULL) return NULL;

    // Start by making a copy of the entire structure,
    // which is essentially a shallow copy.
    htp_cfg_t *copy = malloc(sizeof (htp_cfg_t));
    if (copy == NULL) return NULL;
    memcpy(copy, cfg, sizeof (htp_cfg_t));

    // Now create copies of the hooks' structures.

    if (cfg->hook_request_start != NULL) {
        copy->hook_request_start = htp_hook_copy(cfg->hook_request_start);
        if (copy->hook_request_start == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_line != NULL) {
        copy->hook_request_line = htp_hook_copy(cfg->hook_request_line);
        if (copy->hook_request_line == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_uri_normalize != NULL) {
        copy->hook_request_uri_normalize = htp_hook_copy(cfg->hook_request_uri_normalize);
        if (copy->hook_request_uri_normalize == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_header_data != NULL) {
        copy->hook_request_header_data = htp_hook_copy(cfg->hook_request_header_data);
        if (copy->hook_request_header_data == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_headers != NULL) {
        copy->hook_request_headers = htp_hook_copy(cfg->hook_request_headers);
        if (copy->hook_request_headers == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_body_data != NULL) {
        copy->hook_request_body_data = htp_hook_copy(cfg->hook_request_body_data);
        if (copy->hook_request_body_data == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_file_data != NULL) {
        copy->hook_request_file_data = htp_hook_copy(cfg->hook_request_file_data);
        if (copy->hook_request_file_data == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_trailer != NULL) {
        copy->hook_request_trailer = htp_hook_copy(cfg->hook_request_trailer);
        if (copy->hook_request_trailer == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_trailer_data != NULL) {
        copy->hook_request_trailer_data = htp_hook_copy(cfg->hook_request_trailer_data);
        if (copy->hook_request_trailer_data == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_complete != NULL) {
        copy->hook_request_complete = htp_hook_copy(cfg->hook_request_complete);
        if (copy->hook_request_complete == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_start != NULL) {
        copy->hook_response_start = htp_hook_copy(cfg->hook_response_start);
        if (copy->hook_response_start == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_line != NULL) {
        copy->hook_response_line = htp_hook_copy(cfg->hook_response_line);
        if (copy->hook_response_line == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_header_data != NULL) {
        copy->hook_response_header_data = htp_hook_copy(cfg->hook_response_header_data);
        if (copy->hook_response_header_data == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_headers != NULL) {
        copy->hook_response_headers = htp_hook_copy(cfg->hook_response_headers);
        if (copy->hook_response_headers == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_body_data != NULL) {
        copy->hook_response_body_data = htp_hook_copy(cfg->hook_response_body_data);
        if (copy->hook_response_body_data == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_trailer != NULL) {
        copy->hook_response_trailer = htp_hook_copy(cfg->hook_response_trailer);
        if (copy->hook_response_trailer == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_trailer_data != NULL) {
        copy->hook_response_trailer_data = htp_hook_copy(cfg->hook_response_trailer_data);
        if (copy->hook_response_trailer_data == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_complete != NULL) {
        copy->hook_response_complete = htp_hook_copy(cfg->hook_response_complete);
        if (copy->hook_response_complete == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_transaction_complete != NULL) {
        copy->hook_transaction_complete = htp_hook_copy(cfg->hook_transaction_complete);
        if (copy->hook_transaction_complete == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    if (cfg->hook_log != NULL) {
        copy->hook_log = htp_hook_copy(cfg->hook_log);
        if (copy->hook_log == NULL) {
            htp_config_destroy(copy);
            return NULL;
        }
    }

    return copy;
}

void htp_config_destroy(htp_cfg_t *cfg) {
    if (cfg == NULL) return;

    htp_hook_destroy(cfg->hook_request_start);
    htp_hook_destroy(cfg->hook_request_line);
    htp_hook_destroy(cfg->hook_request_uri_normalize);
    htp_hook_destroy(cfg->hook_request_header_data);
    htp_hook_destroy(cfg->hook_request_headers);
    htp_hook_destroy(cfg->hook_request_body_data);
    htp_hook_destroy(cfg->hook_request_file_data);
    htp_hook_destroy(cfg->hook_request_trailer);
    htp_hook_destroy(cfg->hook_request_trailer_data);
    htp_hook_destroy(cfg->hook_request_complete);
    htp_hook_destroy(cfg->hook_response_start);
    htp_hook_destroy(cfg->hook_response_line);
    htp_hook_destroy(cfg->hook_response_header_data);
    htp_hook_destroy(cfg->hook_response_headers);
    htp_hook_destroy(cfg->hook_response_body_data);
    htp_hook_destroy(cfg->hook_response_trailer);
    htp_hook_destroy(cfg->hook_response_trailer_data);
    htp_hook_destroy(cfg->hook_response_complete);
    htp_hook_destroy(cfg->hook_transaction_complete);
    htp_hook_destroy(cfg->hook_log);

    free(cfg);
}

void *htp_config_get_user_data(htp_cfg_t *cfg) {
    if (cfg == NULL) return NULL;
    return cfg->user_data;
}

void htp_config_register_log(htp_cfg_t *cfg, int (*callback_fn)(htp_log_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_log, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_multipart_parser(htp_cfg_t *cfg) {
    if (cfg == NULL) return;
    htp_config_register_request_headers(cfg, htp_ch_multipart_callback_request_headers);
}

void htp_config_register_request_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_complete, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_body_data, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_file_data(htp_cfg_t *cfg, int (*callback_fn)(htp_file_data_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_file_data, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_uri_normalize(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_uri_normalize, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_header_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_header_data, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_headers, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_line(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_line, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_start(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_start, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_trailer, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_request_trailer_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *d)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_request_trailer_data, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_response_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_response_body_data, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_response_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_response_complete, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_response_header_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_response_header_data, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_response_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_response_headers, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_response_line(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_response_line, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_response_start(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_response_start, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_response_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_response_trailer, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_response_trailer_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *d)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_response_trailer_data, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_transaction_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *)) {
    if (cfg == NULL) return;
    htp_hook_register(&cfg->hook_transaction_complete, (htp_callback_fn_t) callback_fn);
}

void htp_config_register_urlencoded_parser(htp_cfg_t *cfg) {
    if (cfg == NULL) return;
    htp_config_register_request_line(cfg, htp_ch_urlencoded_callback_request_line);
    htp_config_register_request_headers(cfg, htp_ch_urlencoded_callback_request_headers);
}

htp_status_t htp_config_set_extract_request_files(htp_cfg_t *cfg, int extract_request_files, int limit) {
    if (cfg == NULL) return HTP_ERROR;
    if (cfg->tmpdir == NULL) return HTP_ERROR;
    cfg->extract_request_files = extract_request_files;
    cfg->extract_request_files_limit = limit;
    return HTP_OK;
}

void htp_config_set_field_limits(htp_cfg_t *cfg, size_t soft_limit, size_t hard_limit) {
    if (cfg == NULL) return;
    cfg->field_limit_soft = soft_limit;
    cfg->field_limit_hard = hard_limit;
}

void htp_config_set_log_level(htp_cfg_t *cfg, enum htp_log_level_t log_level) {
    if (cfg == NULL) return;
    cfg->log_level = log_level;
}

void htp_config_set_parse_request_auth(htp_cfg_t *cfg, int parse_request_auth) {
    if (cfg == NULL) return;
    cfg->parse_request_auth = parse_request_auth;
}

void htp_config_set_parse_request_cookies(htp_cfg_t *cfg, int parse_request_cookies) {
    if (cfg == NULL) return;
    cfg->parse_request_cookies = parse_request_cookies;
}

void htp_config_set_response_decompression(htp_cfg_t *cfg, int enabled) {
    if (cfg == NULL) return;
    cfg->response_decompression_enabled = enabled;
}

int htp_config_set_server_personality(htp_cfg_t *cfg, enum htp_server_personality_t personality) {
    if (cfg == NULL) return HTP_ERROR;

    switch (personality) {

        case HTP_SERVER_MINIMAL:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;
            break;

        case HTP_SERVER_GENERIC:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            htp_config_set_backslash_convert_slashes(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_decode(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_compress(cfg, HTP_DECODER_URL_PATH, 1);
            break;

        case HTP_SERVER_IDS:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            htp_config_set_backslash_convert_slashes(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_decode(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_compress(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_convert_lowercase(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_utf8_convert_bestfit(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_requestline_leading_whitespace_unwanted(cfg, HTP_DECODER_DEFAULTS, HTP_UNWANTED_IGNORE);
            break;

        case HTP_SERVER_APACHE_2:
            cfg->parse_request_line = htp_parse_request_line_apache_2_2;
            cfg->process_request_header = htp_process_request_header_apache_2_2;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            htp_config_set_backslash_convert_slashes(cfg, HTP_DECODER_URL_PATH, 0);
            htp_config_set_path_separators_decode(cfg, HTP_DECODER_URL_PATH, 0);
            htp_config_set_path_separators_compress(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URL_PATH, 0);

            htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URL_PATH, HTP_URL_DECODE_PRESERVE_PERCENT);
            htp_config_set_url_encoding_invalid_unwanted(cfg, HTP_DECODER_URL_PATH, HTP_UNWANTED_400);
            htp_config_set_control_chars_unwanted(cfg, HTP_DECODER_URL_PATH, HTP_UNWANTED_IGNORE);
            htp_config_set_requestline_leading_whitespace_unwanted(cfg, HTP_DECODER_DEFAULTS, HTP_UNWANTED_400);
            break;

        case HTP_SERVER_IIS_5_1:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            htp_config_set_backslash_convert_slashes(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_decode(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_compress(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URL_PATH, 0);

            htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URL_PATH, HTP_URL_DECODE_PRESERVE_PERCENT);
            htp_config_set_control_chars_unwanted(cfg, HTP_DECODER_URL_PATH, HTP_UNWANTED_IGNORE);
            htp_config_set_requestline_leading_whitespace_unwanted(cfg, HTP_DECODER_DEFAULTS, HTP_UNWANTED_IGNORE);
            break;

        case HTP_SERVER_IIS_6_0:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            htp_config_set_backslash_convert_slashes(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_decode(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_compress(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URL_PATH, 1);

            htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URL_PATH, HTP_URL_DECODE_PRESERVE_PERCENT);
            htp_config_set_u_encoding_unwanted(cfg, HTP_DECODER_URL_PATH, HTP_UNWANTED_400);
            htp_config_set_control_chars_unwanted(cfg, HTP_DECODER_URL_PATH, HTP_UNWANTED_400);
            htp_config_set_requestline_leading_whitespace_unwanted(cfg, HTP_DECODER_DEFAULTS, HTP_UNWANTED_IGNORE);
            break;

        case HTP_SERVER_IIS_7_0:
        case HTP_SERVER_IIS_7_5:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            htp_config_set_backslash_convert_slashes(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_decode(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_path_separators_compress(cfg, HTP_DECODER_URL_PATH, 1);
            htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URL_PATH, 1);

            htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URL_PATH, HTP_URL_DECODE_PRESERVE_PERCENT);
            htp_config_set_url_encoding_invalid_unwanted(cfg, HTP_DECODER_URL_PATH, HTP_UNWANTED_400);
            htp_config_set_control_chars_unwanted(cfg, HTP_DECODER_URL_PATH, HTP_UNWANTED_400);
            htp_config_set_requestline_leading_whitespace_unwanted(cfg, HTP_DECODER_DEFAULTS, HTP_UNWANTED_IGNORE);
            break;

        default:
            return HTP_ERROR;
    }

    // Remember the personality
    cfg->server_personality = personality;

    return HTP_OK;
}

void htp_config_set_tmpdir(htp_cfg_t *cfg, char *tmpdir) {
    if (cfg == NULL) return;
    cfg->tmpdir = tmpdir;
}

void htp_config_set_tx_auto_destroy(htp_cfg_t *cfg, int tx_auto_destroy) {
    if (cfg == NULL) return;
    cfg->tx_auto_destroy = tx_auto_destroy;
}

void htp_config_set_user_data(htp_cfg_t *cfg, void *user_data) {
    if (cfg == NULL) return;
    cfg->user_data = user_data;
}


static int convert_to_0_or_1(int b) {
    if (b) return 1;
    return 0;
}

void htp_config_set_bestfit_map(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, void *map) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].bestfit_map = map;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].bestfit_map = map;
        }
    }
}

void htp_config_set_bestfit_replacement_byte(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int b) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].bestfit_replacement_byte = b;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].bestfit_replacement_byte = b;
        }
    }
}

void htp_config_set_url_encoding_invalid_handling(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_url_encoding_handling_t handling) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].url_encoding_invalid_handling = handling;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].url_encoding_invalid_handling = handling;
        }
    }
}

void htp_config_set_nul_raw_terminates(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].nul_raw_terminates = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].nul_raw_terminates = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_nul_encoded_terminates(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].nul_encoded_terminates = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].nul_encoded_terminates = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_u_encoding_decode(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].u_encoding_decode = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].u_encoding_decode = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_backslash_convert_slashes(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].backslash_convert_slashes = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].backslash_convert_slashes = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_path_separators_decode(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].path_separators_decode = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].path_separators_decode = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_path_separators_compress(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].path_separators_compress = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].path_separators_compress = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_plusspace_decode(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].plusspace_decode = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].plusspace_decode = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_convert_lowercase(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].convert_lowercase = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].convert_lowercase = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_utf8_convert_bestfit(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, int enabled) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].utf8_convert_bestfit = convert_to_0_or_1(enabled);

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].utf8_convert_bestfit = convert_to_0_or_1(enabled);
        }
    }
}

void htp_config_set_u_encoding_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].u_encoding_unwanted = unwanted;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].u_encoding_unwanted = unwanted;
        }
    }
}

void htp_config_set_control_chars_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].u_encoding_unwanted = unwanted;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].u_encoding_unwanted = unwanted;
        }
    }
}

void htp_config_set_url_encoding_invalid_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;
    
    cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted = unwanted;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].url_encoding_invalid_unwanted = unwanted;
        }
    }
}

void htp_config_set_nul_encoded_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].nul_encoded_unwanted = unwanted;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].nul_encoded_unwanted = unwanted;
        }
    }
}

void htp_config_set_nul_raw_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].nul_raw_unwanted = unwanted;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].nul_raw_unwanted = unwanted;
        }
    }
}

void htp_config_set_path_separators_encoded_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].path_separators_encoded_unwanted = unwanted;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].path_separators_encoded_unwanted = unwanted;
        }
    }
}

void htp_config_set_utf8_invalid_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->decoder_cfgs[ctx].utf8_invalid_unwanted = unwanted;

    if (ctx == HTP_DECODER_DEFAULTS) {
        for (size_t i = 0; i < HTP_DECODER_CONTEXTS_MAX; i++) {
            cfg->decoder_cfgs[i].utf8_invalid_unwanted = unwanted;
        }
    }
}

void htp_config_set_requestline_leading_whitespace_unwanted(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, enum htp_unwanted_t unwanted) {
    if (ctx >= HTP_DECODER_CONTEXTS_MAX) return;

    cfg->requestline_leading_whitespace_unwanted = unwanted;
}

void htp_config_set_response_decompression_layer_limit(htp_cfg_t *cfg, int limit) {
    if (cfg == NULL) return;
    cfg->response_decompression_layer_limit = limit;
}
