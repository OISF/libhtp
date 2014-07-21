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
 *
 * @author Ivan Ristic <ivanr@webkreator.com>
 */

#include <iostream>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <gtest/gtest.h>
#include <htp/htp_private.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

static htp_status_t GUnzip_decompressor_callback(htp_tx_data_t *d) {
    bstr **output = (bstr **) htp_tx_get_user_data(d->tx);
    *output = bstr_dup_mem(d->data, d->len);

    return HTP_OK;
}

class GUnzip : public testing::Test {
protected:

    virtual htp_status_t decompressFile(const char *f) {
        // Construct complete file name

        char filename[1025];
        strncpy(filename, home, 1024);
        strncat(filename, "/", 1024 - strlen(filename));
        strncat(filename, f, 1024 - strlen(filename));

        // Load test data

        int fd = open(filename, O_RDONLY | O_BINARY);
        if (fd < 0) {
            //FAIL() << "Unable to open test file";
            return HTP_ERROR;
        }

        struct stat statbuf;
        if (fstat(fd, &statbuf) < 0) {
            //FAIL() << "Unable to stat test file";
            return HTP_ERROR;
        }

        htp_tx_data_t d;
        d.tx = tx;
        d.len = statbuf.st_size;
        d.data = (const unsigned char *) malloc(d.len);
        if (d.data == NULL) {
            //FAIL() << "Memory allocation failed";
            return HTP_ERROR;
        }

        ssize_t bytes_read = read(fd, (void *) d.data, d.len);
        if ((bytes_read < 0)||((size_t)bytes_read != d.len)) {        
            //FAIL() << "Reading from test file failed";
            close(fd);
            return HTP_ERROR;
        }

        close(fd);

        // Decompress

        htp_status_t rc = decompressor->decompress(decompressor, &d);

        free((void *)d.data);

        return rc;
    }

    virtual void SetUp() {
        home = getenv("srcdir");
        if (home == NULL) {
            fprintf(stderr, "This program needs environment variable 'srcdir' set.");
            exit(EXIT_FAILURE);
        }

        cfg = htp_config_create();
        htp_config_set_server_personality(cfg, HTP_SERVER_APACHE_2);

        connp = htp_connp_create(cfg);
        tx = htp_connp_tx_create(connp);
        htp_tx_set_user_data(tx, &output);

        decompressor = htp_gzip_decompressor_create(connp, HTP_COMPRESSION_GZIP);
        decompressor->callback = GUnzip_decompressor_callback;

        o_boxing_wizards = bstr_dup_c("The five boxing wizards jump quickly.");
        output = NULL;
    }

    virtual void TearDown() {
        bstr_free(output);
        bstr_free(o_boxing_wizards);
        decompressor->destroy(decompressor);
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
    }

    bstr *output;

    bstr *o_boxing_wizards;

    htp_connp_t *connp;

    htp_tx_t *tx;

    htp_cfg_t *cfg;

    char *home;

    htp_decompressor_t *decompressor;
};

TEST_F(GUnzip, Minimal) {
    htp_status_t rc = decompressFile("gztest-01-minimal.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

TEST_F(GUnzip, FNAME) {
    htp_status_t rc = decompressFile("gztest-02-fname.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

#if 0

TEST_F(GUnzip, FCOMMENT) {
    htp_status_t rc = decompressFile("gztest-03-fcomment.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

TEST_F(GUnzip, FHCRC) {
    htp_status_t rc = decompressFile("gztest-04-fhcrc.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}
#endif

TEST_F(GUnzip, FEXTRA) {
    htp_status_t rc = decompressFile("gztest-05-fextra.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

TEST_F(GUnzip, FTEXT) {
    htp_status_t rc = decompressFile("gztest-06-ftext.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

#if 0

TEST_F(GUnzip, FRESERVED1) {
    htp_status_t rc = decompressFile("gztest-07-freserved1.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

TEST_F(GUnzip, FRESERVED2) {
    htp_status_t rc = decompressFile("gztest-08-freserved2.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

TEST_F(GUnzip, FRESERVED3) {
    htp_status_t rc = decompressFile("gztest-09-freserved3.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}
#endif

TEST_F(GUnzip, Multipart) {
    htp_status_t rc = decompressFile("gztest-10-multipart.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

#if 0

TEST_F(GUnzip, InvalidMethod) {
    htp_status_t rc = decompressFile("gztest-11-invalid-method.gz.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

TEST_F(GUnzip, InvalidCrc) {
    htp_status_t rc = decompressFile("gztest-12-invalid-crc32.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

TEST_F(GUnzip, InvalidInputSize) {
    htp_status_t rc = decompressFile("gztest-13-invalid-isize.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}
#endif

TEST_F(GUnzip, InvalidExtraFlags) {
    htp_status_t rc = decompressFile("gztest-14-invalid-xfl.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}

TEST_F(GUnzip, InvalidHeaderCrc) {
    htp_status_t rc = decompressFile("gztest-15-invalid-fhcrc.gz");
    ASSERT_EQ(rc, HTP_OK);
    ASSERT_TRUE(output != NULL);
    ASSERT_TRUE(bstr_cmp(o_boxing_wizards, output) == 0);
}
