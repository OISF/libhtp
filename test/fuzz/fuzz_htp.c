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

#include <sys/stat.h>
#include <fcntl.h>

#include <htp/htp.h>


FILE * logfile = NULL;


/**
 * Invoked at the end of every transaction. 
 *
 * @param[in] connp
 */
static int callback_response(htp_tx_t *out_tx) {
    if (out_tx != NULL) {
        char *x = bstr_util_strdup_to_c(out_tx->request_line);
        fprintf(logfile, "%s\n", x);
        free(x);
    }
    return 0;
}

/**
 * Invoked every time LibHTP wants to log. 
 *
 * @param[in] log
 */
static int callback_log(htp_log_t *log) {
    fprintf(logfile, "[%d][code %d][file %s][line %d] %s\n",
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
    size_t SizeReq;
    htp_connp_t * connp;

    //initialize output file
    if (logfile == NULL) {
        logfile = fopen("/dev/null", "w");
        if (logfile == NULL) {
            return 0;
        }
    }

    if (Size < 3) {
        return 0;
    }
    SizeReq = (Data[1] << 8) | Data[2];
    if (Size < 3 + SizeReq) {
        return 0;
    }

    // Create LibHTP configuration
    cfg = htp_config_create();
    if (htp_config_set_server_personality(cfg, Data[0]) != HTP_OK) {
        htp_config_destroy(cfg);
        return 0;
    }
    htp_config_register_response_complete(cfg, callback_response);
    htp_config_register_log(cfg, callback_log);

    connp = htp_connp_create(cfg);
    htp_connp_req_data(connp, 0, Data+3, SizeReq);
    htp_connp_res_data(connp, 0, Data+3+SizeReq, Size - (3+SizeReq) );
    htp_connp_destroy_all(connp);

    // Destroy LibHTP configuration    
    htp_config_destroy(cfg);

    return 0;
}

