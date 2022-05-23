/***************************************************************************
 * Copyright (c) 2009-2010 Open Information Security Foundation
 * Copyright (c) 2010-2013 Qualys, Inc.
 * Copyright (c) 2013-2022 John sanpe.
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

/*
 * This program is a simple example of how to use LibHTP to parse a HTTP
 * connection stream. It uses libnids for TCP reassembly and LibHTP for
 * HTTP parsing.
 *
 * This program is only meant as an demonstration; it is not suitable
 * to be used in production. Furthermore, libnids itself was unreliable
 * in my tests.
 *
 * Compile with:
 *
 *     $ gcc htptest.c -lhtp -lz -lnids -o htptest
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <nids.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../htp/htp.h"
#include "../htp/htp_list.h"
#include "../htp/htp_table.h"
#include "../htp/htp_connection_parser_private.h"

#define DIRECTION_CLIENT    1
#define DIRECTION_SERVER    2

typedef struct chunk_t chunk_t;
typedef struct stream_data stream_data;

/** Data chunk structure */
struct chunk_t {
    char *data;
    size_t len;
    int direction;
    size_t consumed;
};

/** Per-stream data structure */
struct stream_data {
    int id;
    htp_connp_t *connp;
    int direction;
    int fd;
    int chunk_counter;
    int log_level;
    int req_count;
    htp_list_t *chunks;
    htp_list_t *inbound_chunks;
    htp_list_t *outbound_chunks;
};

/** LibHTP parser configuration */
htp_cfg_t *cfg;

/** Connection counter */
int counter = 1000;

/**
 * Free stream data.
 *
 * @param[in] sd
 */
void free_stream_data(stream_data *sd) {
    if (sd == NULL) return;

    // Free stream chunks, if any
    if (sd->chunks != NULL) {
        for (int i = 0, n = htp_list_size(sd->chunks); i < n; i++) {
            chunk_t *chunk = htp_list_get(sd->chunks, i);
            free(chunk->data);
            free(chunk);
        }

        htp_list_destroy(sd->chunks);
        sd->chunks = NULL;
    }

    // Free inbound chunks, if any
    if (sd->inbound_chunks != NULL) {
        for (int i = 0, n = htp_list_size(sd->inbound_chunks); i < n; i++) {
            chunk_t *chunk = htp_list_get(sd->inbound_chunks, i);
            free(chunk->data);
            free(chunk);
        }

        htp_list_destroy(sd->inbound_chunks);
        sd->inbound_chunks = NULL;
    }

    // Free outbound chunks, if any
    if (sd->outbound_chunks != NULL) {
        for (int i = 0, n = htp_list_size(sd->outbound_chunks); i < n; i++) {
            chunk_t *chunk = htp_list_get(sd->outbound_chunks, i);
            free(chunk->data);
            free(chunk);
        }

        htp_list_destroy(sd->outbound_chunks);
        sd->outbound_chunks = NULL;
    }

    // Close the stream file, if we have it open
    if (sd->fd != -1) {
        close(sd->fd);
    }

    free(sd);
}

/**
 * Process as much buffered inbound and outbound data as possible
 * (in that order)
 *
 * @param[in] sd
 */
void process_stored_stream_data(stream_data *sd) {
    int loop = 0;

    do {
        // Reset loop
        loop = 0;

        // Send as much inbound data as possible
        while((sd->connp->in_status == HTP_STREAM_DATA)&&(htp_list_size(sd->inbound_chunks) > 0)) {
            chunk_t *chunk = (chunk_t *)htp_list_get(sd->inbound_chunks, 0);

            int rc = htp_connp_req_data(sd->connp, 0, chunk->data + chunk->consumed, chunk->len - chunk->consumed);
            if (rc == HTP_STREAM_DATA) {
                // The entire chunk was consumed
                htp_list_shift(sd->inbound_chunks);
                free(chunk->data);
                free(chunk);
            } else {
                // Partial consumption
                chunk->consumed = htp_connp_req_data_consumed(sd->connp);
            }
        }

        // Send as much outbound data as possible
        while((sd->connp->out_status == HTP_STREAM_DATA)&&(htp_list_size(sd->outbound_chunks) > 0)) {
            chunk_t *chunk = (chunk_t *)htp_list_get(sd->outbound_chunks, 0);

            int rc = htp_connp_res_data(sd->connp, 0, chunk->data + chunk->consumed, chunk->len - chunk->consumed);
            if (rc == HTP_STREAM_DATA) {
                // The entire chunk was consumed
                htp_list_shift(sd->outbound_chunks);
                free(chunk->data);
                free(chunk);
            } else {
                // Partial consumption
                chunk->consumed = htp_connp_res_data_consumed(sd->connp);
            }

            // Whenever we send some outbound data to the parser,
            // we need to go back and try to send inbound data
            // if we have it.
            loop = 1;
        }
    } while(loop);
}

/**
 * Process a chunk of the connection stream.
 *
 * @param[in] sd
 * @param[in] direction
 * @param[in] hlf
 */
void process_stream_data(stream_data *sd, int direction, struct half_stream *hlf) {
    chunk_t *chunk = NULL;
    int rc;

    //printf("#DATA direction %d bytes %d\n", sd->direction, hlf->count_new);

    if (sd->direction == direction) {
        // Inbound data

        switch(sd->connp->in_status) {
            case HTP_STREAM_NEW :
            case HTP_STREAM_DATA :
                // Send data to parser

                rc = htp_connp_req_data(sd->connp, 0, hlf->data, hlf->count_new);
                if (rc == HTP_STREAM_DATA_OTHER) {
                    // Encountered inbound parsing block

                    // Store partial chunk for later
                    chunk = calloc(1, sizeof(chunk_t));
                    // TODO
                    chunk->len = hlf->count_new - htp_connp_req_data_consumed(sd->connp);
                    chunk->data = malloc(chunk->len);
                    // TODO
                    memcpy(chunk->data, hlf->data + htp_connp_req_data_consumed(sd->connp), chunk->len);
                    htp_list_add(sd->inbound_chunks, chunk);
                } else
                if (rc != HTP_STREAM_DATA) {
                    // Inbound parsing error
                    sd->log_level = 0;
                    fprintf(stderr, "[#%d] Inbound parsing error: %d\n", sd->id, rc);
                    // TODO Write connection to disk
                }
                break;

            case HTP_STREAM_ERROR :
                // Do nothing
                break;

            case HTP_STREAM_DATA_OTHER :
                // Store data for later
                chunk = calloc(1, sizeof(chunk_t));
                // TODO
                chunk->len = hlf->count_new;
                chunk->data = malloc(chunk->len);
                // TODO
                memcpy(chunk->data, hlf->data, chunk->len);
                htp_list_add(sd->inbound_chunks, chunk);
                break;
        }
    } else {
        // Outbound data
        switch(sd->connp->out_status) {
            case HTP_STREAM_NEW :
            case HTP_STREAM_DATA :
                // Send data to parser

                rc = htp_connp_res_data(sd->connp, 0, hlf->data, hlf->count_new);
                if (rc == HTP_STREAM_DATA_OTHER) {
                    // Encountered outbound parsing block

                    // Store partial chunk for later
                    chunk = calloc(1, sizeof(chunk_t));
                    // TODO
                    chunk->len = hlf->count_new - htp_connp_res_data_consumed(sd->connp);
                    chunk->data = malloc(chunk->len);
                    // TODO
                    memcpy(chunk->data, hlf->data + htp_connp_res_data_consumed(sd->connp), chunk->len);
                    htp_list_add(sd->outbound_chunks, chunk);
                } else
                if (rc != HTP_STREAM_DATA) {
                    // Outbound parsing error
                    sd->log_level = 0;
                    fprintf(stderr, "[#%d] Outbound parsing error: %d\n", sd->id, rc);
                }
                break;

            case HTP_STREAM_ERROR :
                // Do nothing
                break;

            case HTP_STREAM_DATA_OTHER :
                // Store data for later
                chunk = calloc(1, sizeof(chunk_t));
                // TODO
                chunk->len = hlf->count_new;
                chunk->data = malloc(chunk->len);
                // TODO
                memcpy(chunk->data, hlf->data, chunk->len);
                htp_list_add(sd->outbound_chunks, chunk);
                break;
        }
    }

    // Process as much stored data as possible
    process_stored_stream_data(sd);
}

/**
 * Called by libnids whenever it has an event we have to handle.
 *
 * @param[in] tcp
 * @param[in] user_data
 */
void tcp_callback (struct tcp_stream *tcp, void **user_data) {
    stream_data *sd = *user_data;

    // New connection
    if (tcp->nids_state == NIDS_JUST_EST) {
        tcp->client.collect++;
        tcp->server.collect++;
        tcp->server.collect_urg++;
        tcp->client.collect_urg++;

        // Allocate custom per-stream data
        sd = calloc(1, sizeof(stream_data));
        sd->id = counter++;
        sd->direction = -1;
        sd->fd = -1;
        sd->log_level = -1;
        sd->chunks = htp_list_array_create(16);
        sd->inbound_chunks = htp_list_array_create(16);
        sd->outbound_chunks = htp_list_array_create(16);
        sd->req_count = 1;

        // Init LibHTP parser
        sd->connp = htp_connp_create(cfg);
        if (sd->connp == NULL) {
            fprintf(stderr, "Failed to create LibHTP parser instance.\n");
            exit(1);
        }

        // Associate TCP stream information with the HTTP connection parser
        htp_connp_set_user_data(sd->connp, sd);

        // Associate TCP stream information with the libnids structures
        *user_data = sd;

        return;
    }

    // Connection close
    if (tcp->nids_state == NIDS_CLOSE) {
        if (sd == NULL) return;

        // Destroy parser
        htp_connp_destroy_all(sd->connp);

        // Free custom per-stream data
        free_stream_data(sd);

        return;
    }

    // Connection close (RST)
    if (tcp->nids_state == NIDS_RESET) {
        if (sd == NULL) return;

        // Destroy parser
        htp_connp_destroy_all(sd->connp);

        // Free custom per-stream data
        free_stream_data(sd);

        return;
    }

    if (tcp->nids_state == NIDS_DATA) {
        struct half_stream *hlf;
        int direction;

        if (tcp->client.count_new) {
            hlf = &tcp->client;
            direction = DIRECTION_SERVER;
        } else {
            hlf = &tcp->server;
            direction = DIRECTION_CLIENT;
        }

        if (sd == NULL) return;

        if (sd->direction == -1) {
            sd->direction = direction;
        }

        // Write data to disk or store for later
        if (sd->fd == -1) {
            // Store data, as we may need it later
            chunk_t *chunk = calloc(1, sizeof(chunk_t));
            // TODO
            chunk->direction = direction;
            chunk->data = malloc(hlf->count_new);
            // TODO
            chunk->len = hlf->count_new;
            memcpy(chunk->data, hlf->data, chunk->len);

            htp_list_add(sd->chunks, chunk);
        } else {
            // No need to store, write directly to file

            if (sd->chunk_counter != 0) {
                write(sd->fd, "\r\n", 2);
            }

            if (sd->direction == direction) {
                write(sd->fd, ">>>\r\n", 5);
            } else {
                write(sd->fd, "<<<\r\n", 5);
            }

            write(sd->fd, hlf->data, hlf->count_new);

            sd->chunk_counter++;
        }

        // Process data
        process_stream_data(sd, direction, hlf);

        return;
    }
}

/**
 * Invoked at the end of every transaction.
 *
 * @param[in] tx
 */
int callback_response(htp_tx_t *tx) {
    stream_data *sd = (stream_data *)htp_tx_get_user_data(tx);

    char *x = bstr_util_strdup_to_c(tx->request_line);
    fprintf(stdout, "[#%d/%d] %s\n", sd->id, sd->req_count, x);
    free(x);

    sd->req_count++;
}

/**
 * Invoked every time LibHTP wants to log.
 *
 * @param[in] log
 */
int callback_log(htp_log_t *log) {
    stream_data *sd = (stream_data *)htp_connp_get_user_data(log->connp);

    if ((sd->log_level == -1)||(sd->log_level > log->level)) {
        sd->log_level = log->level;
    }

    if (log->code != 0) {
        fprintf(stderr, "[#%d/%d][%d][code %d][file %s][line %d] %s\n", sd->id, sd->req_count,
            log->level, log->code, log->file, log->line, log->msg);
    } else {
        fprintf(stderr, "[#%d/%d][%d][file %s][line %d] %s\n", sd->id, sd->req_count,
            log->level, log->file, log->line, log->msg);
    }

    // If this is the first time a log message was generated for this connection,
    // start writing the entire thing to a file on disk.
    if (sd->fd == -1) {
        char filename[256];

        // TODO Use IP addresses and ports in filename
        snprintf(filename, 255, "conn-%d.t", sd->id);

        sd->fd = open(filename, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
        if (sd->fd == -1) {
            fprintf(stderr, "Failed to create file %s: %s\n", filename, strerror(errno));
            exit(1);
        }

        // Write to disk the data we have in memory
        for (int i = 0, n = htp_list_size(sd->chunks); i < n; i++) {
            chunk_t *chunk = htp_list_get(sd->chunks, i);

            if (sd->chunk_counter != 0) {
                write(sd->fd, "\r\n", 2);
            }

            if (sd->direction == chunk->direction) {
                write(sd->fd, ">>>\r\n", 5);
            } else {
                write(sd->fd, "<<<\r\n", 5);
            }

            write(sd->fd, chunk->data, chunk->len);

            sd->chunk_counter++;
        }
    }
}

/**
 * Prints usage.
 */
void print_usage() {
    fprintf(stdout, "Usage: htpMon [-r file] [\"expression\"]\n");
}

/**
 * Main entry point for this program.
 *
 * @param[in] argc
 * @param[in] argv
 */
int main(int argc, char *argv[]) {
    // Check parameters
    if ((argc < 2)||(argc > 4)) {
        print_usage();
        return 1;
    }

    // Configure libnids
    if (argc > 2) {
        if (strcmp(argv[1], "-r") != 0) {
            print_usage();
            return 1;
        }

        nids_params.filename = argv[2];

        if (argc == 4) {
            nids_params.pcap_filter = argv[3];
        }
    } else {
        nids_params.pcap_filter = argv[1];
    }

    // Initialize libnids
    if (!nids_init()) {
        fprintf(stderr, "libnids initialization failed: %s\n", nids_errbuf);
        return 1;
    }

    // Create LibHTP configuration
    cfg = htp_config_create();
    htp_config_set_server_personality(cfg, HTP_SERVER_APACHE_2);

    htp_config_register_response_complete(cfg, callback_response);
    htp_config_register_log(cfg, callback_log);

    // Run libnids
    nids_register_tcp(tcp_callback);
    nids_run();

    // Destroy LibHTP configuration
    htp_config_destroy(cfg);

    return 0;
}

