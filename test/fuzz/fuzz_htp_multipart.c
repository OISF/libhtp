#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "htp/htp.h"
#include "htp/htp_multipart.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) return 0;

    // Use the first byte to determine the boundary length (1-32 bytes)
    size_t boundary_len = (data[0] % 32) + 1;
    if (size < 1 + boundary_len) {
        htp_config_destroy(cfg);
        return 0;
    }

    bstr *boundary = bstr_dup_mem(data + 1, boundary_len);
    if (boundary == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    htp_mpartp_t *parser = htp_mpartp_create(cfg, boundary, 0);
    if (parser == NULL) {
        bstr_free(boundary);
        htp_config_destroy(cfg);
        return 0;
    }

    const uint8_t *mpart_data = data + 1 + boundary_len;
    size_t mpart_size = size - 1 - boundary_len;

    htp_mpartp_parse(parser, mpart_data, mpart_size);
    htp_mpartp_finalize(parser);
    htp_mpartp_destroy(parser);

    bstr_free(boundary);
    htp_config_destroy(cfg);

    return 0;
}
