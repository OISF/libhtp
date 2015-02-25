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
 * Decompress a chunk of gzip-compressed data.
 *
 * @param[in] drec
 * @param[in] d
 * @return HTP_OK on success, HTP_ERROR or some other negative integer on failure.
 */
static htp_status_t htp_gzip_decompressor_decompress(htp_decompressor_gzip_t *drec, htp_tx_data_t *d) {
    size_t consumed = 0;

    // Pass-through the NULL chunk, which indicates the end of the stream.

    if (d->data == NULL) {
        // Prepare data for callback.
        htp_tx_data_t dout;
        dout.tx = d->tx;
        dout.data = NULL;
        dout.len = 0;

        // Send decompressed data to the callback.
        htp_status_t callback_rc = drec->super.callback(&dout);
        if (callback_rc != HTP_OK) {
            inflateEnd(&drec->stream);
            drec->zlib_initialized = 0;

            return callback_rc;
        }

        return HTP_OK;
    }

    // Decompress data.
    int rc = 0;
    drec->stream.next_in = (unsigned char *) (d->data + consumed);
    drec->stream.avail_in = d->len - consumed;

    while (drec->stream.avail_in != 0) {
        // If there's no more data left in the
        // buffer, send that information out.
        if (drec->stream.avail_out == 0) {
            drec->crc = crc32(drec->crc, drec->buffer, GZIP_BUF_SIZE);

            // Prepare data for callback.
            htp_tx_data_t d2;
            d2.tx = d->tx;
            d2.data = drec->buffer;
            d2.len = GZIP_BUF_SIZE;

            // Send decompressed data to callback.
            htp_status_t callback_rc = drec->super.callback(&d2);
            if (callback_rc != HTP_OK) {
                inflateEnd(&drec->stream);
                drec->zlib_initialized = 0;
                
                return callback_rc;
            }

            drec->stream.next_out = drec->buffer;
            drec->stream.avail_out = GZIP_BUF_SIZE;
        }

        rc = inflate(&drec->stream, Z_NO_FLUSH);

        if (rc == Z_STREAM_END) {
            // How many bytes do we have?
            size_t len = GZIP_BUF_SIZE - drec->stream.avail_out;

            // Update CRC
            drec->crc = crc32(drec->crc, drec->buffer, len);

            // Prepare data for the callback.
            htp_tx_data_t d2;
            d2.tx = d->tx;
            d2.data = drec->buffer;
            d2.len = len;

            // Send decompressed data to the callback.
            htp_status_t callback_rc = drec->super.callback(&d2);
            if (callback_rc != HTP_OK) {
                inflateEnd(&drec->stream);
                drec->zlib_initialized = 0;
                
                return callback_rc;
            }

            // TODO Handle trailer.

            return HTP_OK;
        }

        if (rc != Z_OK) {
            htp_log(d->tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "GZip decompressor: inflate failed with %d", rc);

            inflateEnd(&drec->stream);
            drec->zlib_initialized = 0;

            return HTP_ERROR;
        }
    }

    return HTP_OK;
}

/**
 * Shut down gzip decompressor.
 *
 * @param[in] drec
 */
static void htp_gzip_decompressor_destroy(htp_decompressor_gzip_t *drec) {
    if (drec == NULL) return;

    if (drec->zlib_initialized) {
        inflateEnd(&drec->stream);
        drec->zlib_initialized = 0;
    }

    free(drec->buffer);
    free(drec);
}

/**
 * Create a new decompressor instance.
 *
 * @param[in] connp
 * @param[in] format
 * @return New htp_decompressor_t instance on success, or NULL on failure.
 */
htp_decompressor_t *htp_gzip_decompressor_create(htp_connp_t *connp, enum htp_content_encoding_t format) {
    htp_decompressor_gzip_t *drec = calloc(1, sizeof (htp_decompressor_gzip_t));
    if (drec == NULL) return NULL;

    drec->super.decompress = (int (*)(htp_decompressor_t *, htp_tx_data_t *))htp_gzip_decompressor_decompress;
    drec->super.destroy = (void (*)(htp_decompressor_t *))htp_gzip_decompressor_destroy;

    drec->buffer = malloc(GZIP_BUF_SIZE);
    if (drec->buffer == NULL) {
        free(drec);
        return NULL;
    }

    // Initialize zlib.
    int rc;

    if (format == HTP_COMPRESSION_DEFLATE) {
        // Negative values activate raw processing,
        // which is what we need for deflate.
        rc = inflateInit2(&drec->stream, -15);
    } else {
        // Increased windows size activates gzip header processing.
        rc = inflateInit2(&drec->stream, 15 + 32);
    }

    if (rc != Z_OK) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "GZip decompressor: inflateInit2 failed with code %d", rc);

        inflateEnd(&drec->stream);
        free(drec->buffer);
        free(drec);

        return NULL;
    }

    drec->zlib_initialized = 1;
    drec->stream.avail_out = GZIP_BUF_SIZE;
    drec->stream.next_out = drec->buffer;

    #if 0
    if (format == COMPRESSION_DEFLATE) {
        drec->initialized = 1;
    }
    #endif

    return (htp_decompressor_t *) drec;
}
