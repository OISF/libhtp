#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "htp/htp.h"
#include "htp/htp_base64.h"
#include "htp/htp_multipart.h"
#include "htp/htp_private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t type = data[0];
    data++; size--;

    switch (type % 5) {
        case 0: { // base64
            bstr *decoded = htp_base64_decode_mem(data, size);
            if (decoded != NULL) {
                bstr_free(decoded);
            }
            break;
        }
        case 1: { // php parameter
            if (size == 0) break;
            htp_param_t *param = calloc(1, sizeof(htp_param_t));
            if (param == NULL) break;
            param->name = bstr_dup_mem(data, size);
            if (param->name == NULL) {
                free(param);
                break;
            }
            htp_php_parameter_processor(param);
            bstr_free(param->name);
            bstr_free(param->value);
            free(param);
            break;
        }
        case 2: { // mpartp_find_boundary
            if (size == 0) break;
            bstr *content_type = bstr_dup_mem(data, size);
            if (content_type == NULL) break;
            bstr *boundary = NULL;
            uint64_t flags = 0;
            htp_status_t rc = htp_mpartp_find_boundary(content_type, &boundary, &flags);
            if (rc == HTP_OK && boundary != NULL) {
                bstr_free(boundary);
            }
            bstr_free(content_type);
            break;
        }
        case 3: { // protocol
            if (size == 0) break;
            bstr *protocol = bstr_dup_mem(data, size);
            if (protocol) {
                htp_parse_protocol(protocol);
                bstr_free(protocol);
            }
            break;
        }
        case 4: { // status
            if (size == 0) break;
            bstr *status = bstr_dup_mem(data, size);
            if (status) {
                htp_parse_status(status);
                bstr_free(status);
            }
            break;
        }
    }
    return 0;
}
