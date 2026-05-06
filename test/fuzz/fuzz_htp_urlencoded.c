#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "htp/htp.h"
#include "htp/htp_urlencoded.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) return 0;

    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    htp_tx_t *tx = htp_tx_create(connp);
    if (tx == NULL) {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    htp_urlenp_t *urlenp = htp_urlenp_create(tx);
    if (urlenp == NULL) {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    htp_urlenp_parse_complete(urlenp, data, size);
    htp_urlenp_finalize(urlenp);
    htp_urlenp_destroy(urlenp);

    htp_connp_destroy_all(connp);
    htp_config_destroy(cfg);

    return 0;
}
