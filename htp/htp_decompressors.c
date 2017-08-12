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
 *  @brief See if the header has extensions
 *  @return number of bytes to skip
 */
static size_t htp_gzip_decompressor_probe(const unsigned char *data,
                                       size_t data_len)
{
    if (data_len < 4)
        return 0;

    size_t consumed = 0;

    if (data[0] == 0x1f && data[1] == 0x8b && data[3] != 0) {
        if (data[3] & (1 << 3) || data[3] & (1 << 4)) {
            /* skip past
             * - FNAME extension, which is a name ended in a NUL terminator
             * or
             * - FCOMMENT extension, which is a commend ended in a NULL terminator
             */

            size_t len;
            for (len = 10; len < data_len && data[len] != '\0'; len++);
            consumed = len + 1;

            //printf("skipped %u bytes for FNAME/FCOMMENT header (GZIP)\n", (uint)consumed);

        } else if (data[3] & (1 << 1)) {
            consumed = 12;
            //printf("skipped %u bytes for FHCRC header (GZIP)\n", 12);

        } else {
            //printf("GZIP unknown/unsupported flags %02X\n", data[3]);
            consumed = 10;
        }
    }

    if (consumed > data_len)
        return 0;

    return consumed;
}

/**
 *  @brief restart the decompressor
 *  @return 1 if it restarted, 0 otherwise
 */
static int htp_gzip_decompressor_restart(htp_decompressor_gzip_t *drec,
                                         const unsigned char *data,
                                         size_t data_len, size_t *consumed_back)
{
    size_t consumed = 0;
    int rc = 0;

    if (drec->restart < 3) {

        // first retry with the existing type, but now consider the
        // extensions
        if (drec->restart == 0) {
            consumed = htp_gzip_decompressor_probe(data, data_len);

            if (drec->zlib_initialized == HTP_COMPRESSION_GZIP) {
                //printf("GZIP restart, consumed %u\n", (uint)consumed);
                rc = inflateInit2(&drec->stream, 15 + 32);
            } else {
                //printf("DEFLATE restart, consumed %u\n", (uint)consumed);
                rc = inflateInit2(&drec->stream, -15);
            }
            if (rc != Z_OK)
                return 0;

            goto restart;

        // if that still fails, try the other method we support

        } else if (drec->zlib_initialized == HTP_COMPRESSION_DEFLATE) {
            rc = inflateInit2(&drec->stream, 15 + 32);
            if (rc != Z_OK)
                return 0;

            drec->zlib_initialized = HTP_COMPRESSION_GZIP;
            consumed = htp_gzip_decompressor_probe(data, data_len);
#if 0
            printf("DEFLATE -> GZIP consumed %u\n", (uint)consumed);
#endif
            goto restart;

        } else if (drec->zlib_initialized == HTP_COMPRESSION_GZIP) {
            rc = inflateInit2(&drec->stream, -15);
            if (rc != Z_OK)
                return 0;

            drec->zlib_initialized = HTP_COMPRESSION_DEFLATE;
            consumed = htp_gzip_decompressor_probe(data, data_len);
#if 0
            printf("GZIP -> DEFLATE consumed %u\n", (uint)consumed);
#endif
            goto restart;
        }
    }
    return 0;

restart:
#if 0
    gz_header y;
    gz_headerp x = &y;
    int res = inflateGetHeader(&drec->stream, x);
    printf("HEADER res %d x.os %d x.done %d\n", res, x->os, x->done);
#endif
    *consumed_back = consumed;
    drec->restart++;
    return 1;
}

/**
 * Decompress a chunk of gzip-compressed data.
 * If we have more than one decompressor, call this function recursively.
 *
 * @param[in] drec
 * @param[in] d
 * @return HTP_OK on success, HTP_ERROR or some other negative integer on failure.
 */
static htp_status_t htp_gzip_decompressor_decompress(htp_decompressor_gzip_t *drec, htp_tx_data_t *d) {
    size_t consumed = 0;
    int rc = 0;

    // Pass-through the NULL chunk, which indicates the end of the stream.

    if (drec->passthrough) {
        htp_tx_data_t d2;
        d2.tx = d->tx;
        d2.data = d->data;
        d2.len = d->len;
        d2.is_last = d->is_last;

        htp_status_t callback_rc = drec->super.callback(&d2);
        if (callback_rc != HTP_OK) {
            return HTP_ERROR;
        }

        return HTP_OK;
    }

    if (d->data == NULL) {
        // Prepare data for callback.
        htp_tx_data_t dout;
        dout.tx = d->tx;
        dout.data = NULL;
        dout.len = 0;
        dout.is_last = d->is_last;
        if (drec->super.next != NULL && drec->zlib_initialized) {
            return htp_gzip_decompressor_decompress((htp_decompressor_gzip_t *)drec->super.next, &dout);
        } else {
            // Send decompressed data to the callback.
            htp_status_t callback_rc = drec->super.callback(&dout);
            if (callback_rc != HTP_OK) {
                inflateEnd(&drec->stream);
                drec->zlib_initialized = 0;

                return callback_rc;
            }
        }

        return HTP_OK;
    }

restart:
    if (consumed > d->len) {
        htp_log(d->tx->connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "GZip decompressor: consumed > d->len");
        return HTP_ERROR;
    }
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
            d2.is_last = d->is_last;

            //if (drec->super.next != NULL) {
            if (drec->super.next != NULL && drec->zlib_initialized) {
                htp_tx_data_t d3;
                d3.tx = d->tx;
                d3.data = drec->buffer;
                d3.len = GZIP_BUF_SIZE;
                d3.is_last = d->is_last;
                return htp_gzip_decompressor_decompress((htp_decompressor_gzip_t *)drec->super.next, &d3);
            } else {
                // Send decompressed data to callback.
                htp_status_t callback_rc = drec->super.callback(&d2);
                if (callback_rc != HTP_OK) {
                    inflateEnd(&drec->stream);
                    drec->zlib_initialized = 0;

                    return callback_rc;
                }
            }

            drec->stream.next_out = drec->buffer;
            drec->stream.avail_out = GZIP_BUF_SIZE;
        }

        if (drec->zlib_initialized) {
            rc = inflate(&drec->stream, Z_NO_FLUSH);
        }
        if (rc == Z_STREAM_END) {
            // How many bytes do we have?
            size_t len = GZIP_BUF_SIZE - drec->stream.avail_out;

            // Update CRC

            // Prepare data for the callback.
            htp_tx_data_t d2;
            d2.tx = d->tx;
            d2.data = drec->buffer;
            d2.len = len;
            d2.is_last = d->is_last;

            if (drec->super.next != NULL && drec->zlib_initialized) {
                htp_tx_data_t d3;
                d3.tx = d->tx;
                d3.data = drec->buffer;
                d3.len = len;
                d3.is_last = d->is_last;
                return htp_gzip_decompressor_decompress((htp_decompressor_gzip_t *)drec->super.next, &d3);

            } else {
                // Send decompressed data to the callback.
                htp_status_t callback_rc = drec->super.callback(&d2);
                if (callback_rc != HTP_OK) {
                    inflateEnd(&drec->stream);
                    drec->zlib_initialized = 0;

                    return callback_rc;
                }
            }
            // TODO Handle trailer.

            return HTP_OK;
        }
        else if (rc != Z_OK) {
            htp_log(d->tx->connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "GZip decompressor: inflate failed with %d", rc);
            inflateEnd(&drec->stream);

            // see if we want to restart the decompressor
            if (htp_gzip_decompressor_restart(drec,
                                              d->data, d->len, &consumed) == 1)
            {
                // we'll be restarting the compressor
                goto restart;
            }

            drec->zlib_initialized = 0;

            // all our inflate attempts have failed, simply
            // pass the raw data on to the callback in case
            // it's not compressed at all

            htp_tx_data_t d2;
            d2.tx = d->tx;
            d2.data = d->data;
            d2.len = d->len;
            d2.is_last = d->is_last;

            htp_status_t callback_rc = drec->super.callback(&d2);
            if (callback_rc != HTP_OK) {
                return HTP_ERROR;
            }

            /* successfully passed through, lets continue doing that */
            drec->passthrough = 1;
            return HTP_OK;
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
    drec->super.next = NULL;

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

    drec->zlib_initialized = format;
    drec->stream.avail_out = GZIP_BUF_SIZE;
    drec->stream.next_out = drec->buffer;

    #if 0
    if (format == COMPRESSION_DEFLATE) {
        drec->initialized = 1;
    }
    #endif

    return (htp_decompressor_t *) drec;
}
