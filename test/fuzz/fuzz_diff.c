/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz harness for libhtp
 */


#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "htp/htp.h"
#include "test/test.h"
#include "fuzz_htp.h"
#include "htp/htp_private.h"

FILE * logfile = NULL;


/**
 * Invoked at the end of every transaction.
 *
 * @param[in] connp
 */
static int HTPCallbackResponse(htp_tx_t *out_tx) {
    if (out_tx != NULL) {
        char *x = bstr_util_strdup_to_c(out_tx->request_line);
        fprintf(logfile, "HTPCallbackResponse %s\n", x);
        free(x);
    }
    return 0;
}

static int HTPCallbackRequestHeaderData(htp_tx_data_t *tx_data)
{
    fprintf(logfile, "HTPCallbackRequestHeaderData %"PRIuMAX"\n", (uintmax_t)tx_data->len);
    if (tx_data->len > 0) {
        fprintf(logfile, "HTPCallbackRequestHeaderData %x %x\n", tx_data->data[0], tx_data->data[(uintmax_t)tx_data->len-1]);
    }
    return 0;
}

static int HTPCallbackResponseHeaderData(htp_tx_data_t *tx_data)
{
    fprintf(logfile, "HTPCallbackResponseHeaderData %"PRIuMAX"\n", (uintmax_t)tx_data->len);
    if (tx_data->len > 0) {
        fprintf(logfile, "HTPCallbackResponseHeaderData %x %x\n", tx_data->data[0], tx_data->data[(uintmax_t)tx_data->len-1]);
    }
    return 0;
}

static int HTPCallbackRequestHasTrailer(htp_tx_t *tx)
{
    fprintf(logfile, "HTPCallbackRequestHasTrailer\n");
    return 0;
}

static int HTPCallbackResponseHasTrailer(htp_tx_t *tx)
{
    fprintf(logfile, "HTPCallbackResponseHasTrailer\n");
    return 0;
}

static int HTPCallbackRequestBodyData(htp_tx_data_t *tx_data)
{
    fprintf(logfile, "HTPCallbackRequestBodyData %"PRIuMAX"\n", (uintmax_t)tx_data->len);
    if (tx_data->len > 0 && tx_data->data != NULL) {
        fprintf(logfile, "HTPCallbackRequestBodyData %x %x\n", tx_data->data[0], tx_data->data[(uintmax_t)tx_data->len-1]);
    }
    return 0;
}

static int HTPCallbackResponseBodyData(htp_tx_data_t *tx_data)
{
    fprintf(logfile, "HTPCallbackResponseBodyData %"PRIuMAX"\n", (uintmax_t)tx_data->len);
    if (tx_data->len > 0 && tx_data->data != NULL) {
        fprintf(logfile, "HTPCallbackResponseBodyData %x %x\n", tx_data->data[0], tx_data->data[(uintmax_t)tx_data->len-1]);
    }
    return 0;
}

static int HTPCallbackRequestStart(htp_tx_t *tx)
{
    fprintf(logfile, "HTPCallbackRequestStart\n");
    return 0;
}

static int HTPCallbackRequest(htp_tx_t *tx)
{
    fprintf(logfile, "HTPCallbackRequest\n");
    return 0;
}

static int HTPCallbackResponseStart(htp_tx_t *tx)
{
    fprintf(logfile, "HTPCallbackResponseStart\n");
    return 0;
}

static int HTPCallbackRequestLine(htp_tx_t *tx)
{
    fprintf(logfile, "HTPCallbackRequestLine\n");
    return 0;
}

/**
 * Invoked every time LibHTP wants to log.
 *
 * @param[in] log
 */
static int HTPCallbackLog(htp_log_t *log) {
    fprintf(logfile, "HTPCallbackLog [%d][code %d][file %s][line %d] %s\n",
        log->level, log->code, log->file, log->line, log->msg);
    return 0;
}

void fuzz_openFile(const char * name) {
    if (logfile != NULL) {
        fclose(logfile);
    }
    logfile = fopen(name, "w");
}

htp_cfg_t *cfg;

static void libhtpFuzzInit() {
    logfile = fopen("/dev/null", "w");
    if (logfile == NULL) {
        abort();
    }
    // Create LibHTP configuration
    cfg = htp_config_create();
    if (htp_config_set_server_personality(cfg, HTP_SERVER_IDS) != HTP_OK) {
        htp_config_destroy(cfg);
        return;
    }
    htp_config_register_log(cfg, HTPCallbackLog);
    htp_config_register_request_header_data(cfg, HTPCallbackRequestHeaderData);
    htp_config_register_request_trailer_data(cfg, HTPCallbackRequestHeaderData);
    htp_config_register_response_header_data(cfg, HTPCallbackResponseHeaderData);
    htp_config_register_response_trailer_data(cfg, HTPCallbackResponseHeaderData);
    htp_config_register_request_trailer(cfg, HTPCallbackRequestHasTrailer);
    htp_config_register_response_trailer(cfg, HTPCallbackResponseHasTrailer);
    htp_config_register_request_body_data(cfg, HTPCallbackRequestBodyData);
    htp_config_register_response_body_data(cfg, HTPCallbackResponseBodyData);
    htp_config_register_request_start(cfg, HTPCallbackRequestStart);
    htp_config_register_request_complete(cfg, HTPCallbackRequest);
    htp_config_register_response_start(cfg, HTPCallbackResponseStart);
    htp_config_register_response_complete(cfg, HTPCallbackResponse);
    htp_config_register_request_line(cfg, HTPCallbackRequestLine);
    setenv("srcdir", ".", 1);
}

static htp_connp_t * libhtpFuzzRun(const uint8_t *Data, size_t Size) {
    htp_connp_t * connp;
    int rc;
    test_t test;

    connp = htp_connp_create(cfg);
    htp_connp_set_user_data(connp, (void *) 0x02);
    htp_connp_open(connp, (const char *) "192.168.2.3", 12345, (const char *) "192.168.2.2", 80, NULL);

    test.buf = (char *)Data;
    test.len = Size;
    test.pos = 0;
    test.chunk = NULL;

    // Find all chunks and feed them to the parser
    int in_data_other = 0;
    char *in_data = NULL;
    size_t in_data_len = 0;
    size_t in_data_offset = 0;
    int out_data_other = 0;
    char *out_data = NULL;
    size_t out_data_len = 0;
    size_t out_data_offset = 0;

    for (;;) {
        if (test_next_chunk(&test) <= 0) {
            break;
        }
        if (test.chunk_len == 0) {
            continue;
        }
        if (test.chunk_direction == CLIENT) {
            if (in_data_other) {
                break;
            }
            rc = htp_connp_req_data(connp, NULL, test.chunk, test.chunk_len);
            if (rc == HTP_STREAM_ERROR) {
                break;
            }
            if (rc == HTP_STREAM_DATA_OTHER) {
                // Parser needs to see the outbound stream in order to continue
                // parsing the inbound stream.
                in_data_other = 1;
                in_data = test.chunk;
                in_data_len = test.chunk_len;
                in_data_offset = htp_connp_req_data_consumed(connp);
            }
        } else {
            if (out_data_other) {
                if (out_data == NULL) {
                    rc = htp_connp_res_data(connp, NULL, NULL, out_data_len - out_data_offset);
                } else {
                    rc = htp_connp_res_data(connp, NULL, out_data + out_data_offset, out_data_len - out_data_offset);
                }
                if (rc == HTP_STREAM_ERROR) {
                    break;
                }
                out_data_other = 0;
            }
            rc = htp_connp_res_data(connp, NULL, test.chunk, test.chunk_len);
            if (rc == HTP_STREAM_ERROR) {
                break;
            }
            if (rc == HTP_STREAM_DATA_OTHER) {
                // Parser needs to see the outbound stream in order to continue
                // parsing the inbound stream.
                out_data_other = 1;
                out_data = test.chunk;
                out_data_len = test.chunk_len;
                out_data_offset = htp_connp_res_data_consumed(connp);
            }
            if (in_data_other) {
                if (in_data == NULL) {
                    rc = htp_connp_req_data(connp, NULL, NULL, in_data_len - in_data_offset);
                } else {
                    rc = htp_connp_req_data(connp, NULL, in_data + in_data_offset, in_data_len - in_data_offset);
                }
                if (rc == HTP_STREAM_ERROR) {
                    break;
                }
                in_data_other = 0;
            }
        }
    }
    if (out_data_other) {
        if (out_data == NULL) {
            (void) htp_connp_res_data(connp, NULL, NULL, out_data_len - out_data_offset);
        } else {
            (void) htp_connp_res_data(connp, NULL, out_data + out_data_offset, out_data_len - out_data_offset);
        }
    }

    htp_connp_close(connp, NULL);
    return connp;
}

void* libhtprsFuzzRun(const uint8_t *Data, uint32_t Size);
void* libhtprsFuzzConnp(void *);
size_t htp_connp__rstx_size(void *);
void * htp_connp__rstx(void *, size_t);
void * htp_tx_request_method(void *);
void * htp_tx_request_uri(void *);
void * htp_tx_request_protocol(void *);
void * htp_tx_response_protocol(void *);
void * htp_tx_response_status(void *);
size_t htp_tx_request_headers_size(void *);
void *htp_tx_request_header_index(void *, size_t);
size_t htp_tx_response_headers_size(void *);
void *htp_tx_response_header_index(void *, size_t);
void * htp_header_name(void *);
void * htp_header_value(void *);
size_t bstr_len_rs(void *);
uint8_t * bstr_ptr_rs(void *);
void libhtprsFreeFuzzRun(void *t);

static int bstrDiff(void* rsbstr, bstr * cbstr, const char *field) {
    if (rsbstr == NULL && cbstr == NULL) {
        return 0;
    }
    size_t len =  bstr_len(cbstr);
    uint8_t * rsptr = bstr_ptr_rs(rsbstr);
    uint8_t * cptr = bstr_ptr(cbstr);
    if (bstr_len_rs(rsbstr) != len) {
        fprint_raw_data(stdout, "c=", cptr, len);
        fprint_raw_data(stdout, "rust=", rsptr, bstr_len_rs(rsbstr));
        printf("Assertion failure: Bstr %s lengths are different %zu vs %zu\n", field, bstr_len_rs(rsbstr), len);
        return 1;
    }
    for (size_t i=0; i<len; i++) {
        if (rsptr[i] != cptr[i]) {
            fprint_raw_data(stdout, "c=", cptr, len);
            fprint_raw_data(stdout, "rust=", rsptr, bstr_len_rs(rsbstr));
            printf("Assertion failure: Bstr %s index %zu are different %02x vs %02x\n", field, i, rsptr[i], cptr[i]);
            return 1;
        }
    }
    return 0;
}

static int txDiff(void* rstx, htp_tx_t * ctx) {
    if (bstrDiff(htp_tx_request_method(rstx), ctx->request_method, "methods")) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        abort();
#endif
        return 1;
    }
    if (bstrDiff(htp_tx_request_uri(rstx), ctx->request_uri, "uri")) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        abort();
#endif
        return 1;
    }
    if (bstrDiff(htp_tx_request_protocol(rstx), ctx->request_protocol, "protocol_request")) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        abort();
#endif
        return 1;
    }
    if (bstrDiff(htp_tx_response_protocol(rstx), ctx->response_protocol, "protocol_response")) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        abort();
#endif
        return 1;
    }
    if (bstrDiff(htp_tx_response_status(rstx), ctx->response_status, "status")) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        abort();
#endif
        return 1;
    }

    uint32_t nbhc = htp_table_size(ctx->request_headers);
    uint32_t rsnbh = htp_tx_request_headers_size(rstx);
    if (rsnbh != nbhc) {
        printf("Assertion failure: got nbheaders c=%d versus rust=%d\n", nbhc, rsnbh);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        abort();
#endif
        return 1;
    }

    for (uint32_t i = 0; i < nbhc; i++) {
        htp_header_t *h = (htp_header_t *) htp_table_get_index(ctx->request_headers, i, NULL);
        void *rsh = htp_tx_request_header_index(rstx, (size_t) i);
        if (bstrDiff(htp_header_name(rsh), h->name, "header-name")) {
            printf("request header %d is different\n", i);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            abort();
#endif
            return 1;
        }
        if (bstrDiff(htp_header_value(rsh), h->value, "header-value")) {
            printf("request header %d is different\n", i);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            abort();
#endif
            return 1;
        }
    }

    nbhc = htp_table_size(ctx->response_headers);
    rsnbh = htp_tx_response_headers_size(rstx);
    if (rsnbh != nbhc) {
        printf("Assertion failure: got nbheaders c=%d versus rust=%d\n", nbhc, rsnbh);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        abort();
#endif
        return 1;
    }

    for (uint32_t i = 0; i < nbhc; i++) {
        htp_header_t *h = (htp_header_t *) htp_table_get_index(ctx->response_headers, i, NULL);
        void *rsh = htp_tx_response_header_index(rstx, (size_t) i);
        if (bstrDiff(htp_header_name(rsh), h->name, "header-name")) {
            printf("response header %d is different\n", i);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            abort();
#endif
            return 1;
        }
        if (bstrDiff(htp_header_value(rsh), h->value, "header-value")) {
            printf("response header %d is different\n", i);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            abort();
#endif
            return 1;
        }
    }

    return 0;
}

static int connDiff(void* rsconnp, htp_conn_t * conn) {
    uint32_t rs = htp_connp__rstx_size(rsconnp);
    uint32_t c = htp_list_size(conn->transactions);
    if (rs != c) {
        printf("Assertion failure: got nbtx c=%d versus rust=%d\n", c, rs);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        abort();
#endif
        return 1;
    }
    for (uint32_t i = 0; i < c; i++) {
        htp_tx_t *ctx = (htp_tx_t *) htp_list_get(conn->transactions, i);
        void *rstx = htp_connp__rstx(rsconnp, (size_t) i);
        if (txDiff(rstx, ctx)) {
            printf("tx %d is different\n", i);
            return 1;
        }
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    //initialize output file
    if (logfile == NULL) {
        libhtpFuzzInit();
    }

    htp_connp_t * connp = libhtpFuzzRun(Data, Size);
    htp_conn_t * conn = htp_connp_get_connection(connp);

    void* rstest = libhtprsFuzzRun(Data, Size);
    void * rsconnp = libhtprsFuzzConnp(rstest);
    if (connDiff(rsconnp, conn)) {
        printf("results are different\n");
    }
    libhtprsFreeFuzzRun(rsconnp);

    htp_connp_destroy_all(connp);

    return 0;
}

