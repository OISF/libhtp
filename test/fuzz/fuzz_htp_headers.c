#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "htp/htp.h"
#include "htp/htp_private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t type = data[0];
    data++; size--;

    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) return 0;

    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    htp_tx_t *tx = htp_connp_tx_create(connp);
    if (tx == NULL) {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }
    connp->in_tx = tx;

    if (tx->request_headers == NULL) {
        tx->request_headers = htp_table_create(4);
    }
    
    if (tx->request_headers == NULL) {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    bstr *value = bstr_dup_mem(data, size);
    if (value == NULL) {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    htp_header_t *h = calloc(1, sizeof(htp_header_t));
    if (h == NULL) {
        bstr_free(value);
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }
    
    if (type % 2 == 0) {
        h->name = bstr_dup_c("cookie");
    } else {
        h->name = bstr_dup_c("authorization");
    }

    if (h->name == NULL) {
        free(h);
        bstr_free(value);
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }
    h->value = value;
    if (htp_table_add(tx->request_headers, h->name, h) != HTP_OK) {
        bstr_free(h->name);
        free(h);
        bstr_free(value);
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    if (type % 2 == 0) {
        htp_parse_cookies_v0(connp);
    } else {
        htp_parse_authorization(connp);
    }

    htp_connp_destroy_all(connp);
    htp_config_destroy(cfg);

    return 0;
}
