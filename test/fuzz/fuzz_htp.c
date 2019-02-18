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
    return 0;
}

static int HTPCallbackResponseHeaderData(htp_tx_data_t *tx_data)
{
    fprintf(logfile, "HTPCallbackResponseHeaderData %"PRIuMAX"\n", (uintmax_t)tx_data->len);
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
    return 0;
}

static int HTPCallbackResponseBodyData(htp_tx_data_t *tx_data)
{
    fprintf(logfile, "HTPCallbackResponseBodyData %"PRIuMAX"\n", (uintmax_t)tx_data->len);
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

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    htp_cfg_t *cfg;
    htp_connp_t * connp;
    int rc;
    test_t test;

    //initialize output file
    if (logfile == NULL) {
        logfile = fopen("/dev/null", "w");
        if (logfile == NULL) {
            abort();
        }
    }

    // Create LibHTP configuration
    cfg = htp_config_create();
    if (htp_config_set_server_personality(cfg, HTP_SERVER_IDS) != HTP_OK) {
        htp_config_destroy(cfg);
        return 0;
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
                rc = htp_connp_res_data(connp, NULL, out_data + out_data_offset, out_data_len - out_data_offset);
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
                rc = htp_connp_req_data(connp, NULL, in_data + in_data_offset, in_data_len - in_data_offset);
                if (rc == HTP_STREAM_ERROR) {
                    break;
                }
                in_data_other = 0;
            }
        }
    }
    if (out_data_other) {
        htp_connp_res_data(connp, NULL, out_data + out_data_offset, out_data_len - out_data_offset);
    }

    htp_connp_destroy_all(connp);
    // Destroy LibHTP configuration    
    htp_config_destroy(cfg);

    return 0;
}

