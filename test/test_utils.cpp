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
 * @brief Tests for various utility functions.
 *
 * @author Craig Forbes <cforbes@qualys.com>
 * @author Ivan Ristic <ivanr@webkreator.com>
 */

#include <iostream>
#include <gtest/gtest.h>
#include <htp/htp_private.h>

TEST(Utf8, SingleByte) {
    uint32_t state = HTP_UTF8_ACCEPT;
    uint32_t codep;
    uint32_t result;

    result = htp_utf8_decode(&state, &codep, 0x00);
    EXPECT_EQ(0, result);
    EXPECT_EQ(HTP_UTF8_ACCEPT, state);
    EXPECT_EQ(0, codep);
}

TEST(Base64, Single) {
    EXPECT_EQ(62, htp_base64_decode_single('+'));
    EXPECT_EQ(63, htp_base64_decode_single('/'));
    EXPECT_EQ(-1, htp_base64_decode_single(','));
    EXPECT_EQ(-1, htp_base64_decode_single(0));
    EXPECT_EQ(-1, htp_base64_decode_single('~'));
    EXPECT_EQ(26, htp_base64_decode_single('a'));
    EXPECT_EQ(0, htp_base64_decode_single('A'));
}

TEST(Base64, Decode) {
    const char *input = "dGhpcyBpcyBhIHRlc3QuLg==";
    bstr *out = htp_base64_decode_mem(input, strlen(input));
    EXPECT_EQ(0, bstr_cmp_c(out, "this is a test.."));
    bstr_free(out);
}

TEST(UtilTest, Separator) {
    EXPECT_EQ(0, htp_is_separator('a'));
    EXPECT_EQ(0, htp_is_separator('^'));
    EXPECT_EQ(0, htp_is_separator('-'));
    EXPECT_EQ(0, htp_is_separator('_'));
    EXPECT_EQ(0, htp_is_separator('&'));
    EXPECT_EQ(1, htp_is_separator('('));
    EXPECT_EQ(1, htp_is_separator('\\'));
    EXPECT_EQ(1, htp_is_separator('/'));
    EXPECT_EQ(1, htp_is_separator('='));
    EXPECT_EQ(1, htp_is_separator('\t'));
}

TEST(UtilTest, Text) {
    EXPECT_EQ(1, htp_is_text('\t'));
    EXPECT_EQ(1, htp_is_text('a'));
    EXPECT_EQ(1, htp_is_text('~'));
    EXPECT_EQ(1, htp_is_text(' '));
    EXPECT_EQ(0, htp_is_text('\n'));
    EXPECT_EQ(0, htp_is_text('\r'));
    EXPECT_EQ(0, htp_is_text('\r'));
    EXPECT_EQ(0, htp_is_text(31));
}

TEST(UtilTest, Token) {
    EXPECT_EQ(1, htp_is_token('a'));
    EXPECT_EQ(1, htp_is_token('&'));
    EXPECT_EQ(1, htp_is_token('+'));
    EXPECT_EQ(0, htp_is_token('\t'));
    EXPECT_EQ(0, htp_is_token('\n'));
}

TEST(UtilTest, Chomp) {
    char data[100];
    size_t len;
    int result;

    strcpy(data, "test\r\n");
    len = strlen(data);
    result = htp_chomp((unsigned char *) data, &len);
    EXPECT_EQ(2, result);
    EXPECT_EQ(4, len);

    strcpy(data, "test\r\n\n");
    len = strlen(data);
    result = htp_chomp((unsigned char *) data, &len);
    EXPECT_EQ(2, result);
    EXPECT_EQ(4, len);

    strcpy(data, "test\r\n\r\n");
    len = strlen(data);
    result = htp_chomp((unsigned char *) data, &len);
    EXPECT_EQ(2, result);
    EXPECT_EQ(4, len);

    strcpy(data, "te\nst");
    len = strlen(data);
    result = htp_chomp((unsigned char *) data, &len);
    EXPECT_EQ(0, result);
    EXPECT_EQ(5, len);

    strcpy(data, "foo\n");
    len = strlen(data);
    result = htp_chomp((unsigned char *) data, &len);
    EXPECT_EQ(1, result);
    EXPECT_EQ(3, len);

    strcpy(data, "arfarf");
    len = strlen(data);
    result = htp_chomp((unsigned char *) data, &len);
    EXPECT_EQ(0, result);
    EXPECT_EQ(6, len);

    strcpy(data, "");
    len = strlen(data);
    result = htp_chomp((unsigned char *) data, &len);
    EXPECT_EQ(0, result);
    EXPECT_EQ(0, len);
}

TEST(UtilTest, Space) {
    EXPECT_EQ(0, htp_is_space('a'));
    EXPECT_EQ(1, htp_is_space(' '));
    EXPECT_EQ(1, htp_is_space('\f'));
    EXPECT_EQ(1, htp_is_space('\n'));
    EXPECT_EQ(1, htp_is_space('\r'));
    EXPECT_EQ(1, htp_is_space('\t'));
    EXPECT_EQ(1, htp_is_space('\v'));
}

TEST(UtilTest, Method) {
    bstr *method = bstr_dup_c("GET");

    EXPECT_EQ(HTP_M_GET, htp_convert_method_to_number(method));

    bstr_free(method);
}

TEST(UtilTest, IsLineEmpty) {
    char data[100];
    strcpy(data, "arfarf");
    EXPECT_EQ(0, htp_is_line_empty((unsigned char*) data, 6));

    strcpy(data, "\r\n");
    EXPECT_EQ(1, htp_is_line_empty((unsigned char*) data, 2));
    strcpy(data, "\r");
    EXPECT_EQ(1, htp_is_line_empty((unsigned char*) data, 1));
    EXPECT_EQ(0, htp_is_line_empty((unsigned char*) data, 0));

}

TEST(UtilTest, IsLineWhitespace) {
    char data[100];
    strcpy(data, "arfarf");
    EXPECT_EQ(0, htp_is_line_whitespace((unsigned char*) data, 6));

    strcpy(data, "\r\n");
    EXPECT_EQ(1, htp_is_line_whitespace((unsigned char*) data, 2));
    strcpy(data, "\r");
    EXPECT_EQ(1, htp_is_line_whitespace((unsigned char*) data, 1));
    EXPECT_EQ(1, htp_is_line_whitespace((unsigned char*) data, 0));
}

TEST(UtilTest, ParsePositiveIntegerWhitespace) {
    EXPECT_EQ(123, htp_parse_positive_integer_whitespace(
            (unsigned char*) "123   ", 6, 10));
    EXPECT_EQ(123, htp_parse_positive_integer_whitespace(
            (unsigned char*) "   123", 6, 10));
    EXPECT_EQ(123, htp_parse_positive_integer_whitespace(
            (unsigned char*) "   123   ", 9, 10));
    EXPECT_EQ(-1, htp_parse_positive_integer_whitespace(
            (unsigned char*) "a123", 4, 10));
    EXPECT_EQ(-1001, htp_parse_positive_integer_whitespace(
            (unsigned char*) "   \t", 4, 10));
    EXPECT_EQ(-1002, htp_parse_positive_integer_whitespace(
            (unsigned char*) "123b ", 5, 10));

    EXPECT_EQ(-1, htp_parse_positive_integer_whitespace(
            (unsigned char*) "   a123   ", 9, 10));
    EXPECT_EQ(-1002, htp_parse_positive_integer_whitespace(
            (unsigned char*) "   123b   ", 9, 10));

    EXPECT_EQ(0x123, htp_parse_positive_integer_whitespace(
            (unsigned char*) "   123   ", 9, 16));
}

TEST(UtilTest, ParseContentLength) {
    bstr *str = bstr_dup_c("134");

    EXPECT_EQ(134, htp_parse_content_length(str));

    bstr_free(str);
}

TEST(UtilTest, ParseChunkedLength) {
    EXPECT_EQ(0x12a5, htp_parse_chunked_length((unsigned char*) "12a5", 4));
}

TEST(UtilTest, IsLineFolded) {
    EXPECT_EQ(-1, htp_connp_is_line_folded((unsigned char*) "", 0));
    EXPECT_EQ(1, htp_connp_is_line_folded((unsigned char*) "\tline", 5));
    EXPECT_EQ(1, htp_connp_is_line_folded((unsigned char*) " line", 5));
    EXPECT_EQ(0, htp_connp_is_line_folded((unsigned char*) "line ", 5));
}

static void free_htp_uri_t(htp_uri_t **urip) {
    htp_uri_t *uri = *urip;

    if (uri == NULL) {
        return;
    }
    bstr_free(uri->scheme);
    bstr_free(uri->username);
    bstr_free(uri->password);
    bstr_free(uri->hostname);
    bstr_free(uri->port);
    bstr_free(uri->path);
    bstr_free(uri->query);
    bstr_free(uri->fragment);

    free(uri);
    *urip = NULL;
}

struct uri_expected {
    const char *scheme;
    const char *username;
    const char *password;
    const char *hostname;
    const char *port;
    const char *path;
    const char *query;
    const char *fragment;
};

struct uri_test {
    const char *uri;
    uri_expected expected;
};

bool bstr_equal_c(const bstr *b, const char *c) {
    if ((c == NULL) || (b == NULL)) {
        return (c == NULL) && (b == NULL);
    } else {
        return (0 == bstr_cmp_c(b, c));
    }
}

void append_message(std::ostream & o,
        const char *label, const char *expected, bstr *actual) {
    o << label << " missmatch: ";
    if (expected != NULL) {
        o << "'" << expected << "'";
    } else {
        o << "<NULL>";
    }
    o << " != ";
    if (actual != NULL) {
        o << "'";
        o.write((const char *) bstr_ptr(actual), bstr_len(actual));
        o << "'";
    } else {
        o << "<NULL>";
    }
    o << std::endl;
}

static ::testing::AssertionResult UriIsExpected(const char *expected_var,
        const char *actual_var,
        const uri_expected &expected,
        const htp_uri_t *actual) {
    std::stringstream msg;
    bool equal = true;

    if (!bstr_equal_c(actual->scheme, expected.scheme)) {
        equal = false;
        append_message(msg, "scheme", expected.scheme, actual->scheme);
    }

    if (!bstr_equal_c(actual->username, expected.username)) {
        equal = false;
        append_message(msg, "username", expected.username, actual->username);
    }

    if (!bstr_equal_c(actual->password, expected.password)) {
        equal = false;
        append_message(msg, "password", expected.password, actual->password);
    }

    if (!bstr_equal_c(actual->hostname, expected.hostname)) {
        equal = false;
        append_message(msg, "hostname", expected.hostname, actual->hostname);
    }

    if (!bstr_equal_c(actual->port, expected.port)) {
        equal = false;
        append_message(msg, "port", expected.port, actual->port);
    }

    if (!bstr_equal_c(actual->path, expected.path)) {
        equal = false;
        append_message(msg, "path", expected.path, actual->path);
    }

    if (!bstr_equal_c(actual->query, expected.query)) {
        equal = false;
        append_message(msg, "query", expected.query, actual->query);
    }

    if (!bstr_equal_c(actual->fragment, expected.fragment)) {
        equal = false;
        append_message(msg, "fragment", expected.fragment, actual->fragment);
    }

    if (equal) {
        return ::testing::AssertionSuccess();
    } else {
        return ::testing::AssertionFailure() << msg.str();
    }
}

struct uri_test uri_tests[] = {
    {"http://user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag",
        {"http", "user", "pass", "www.example.com", "1234", "/path1/path2", "a=b&c=d", "frag"}},
    {"http://host.com/path",
        {"http", NULL, NULL, "host.com", NULL, "/path", NULL, NULL}},
    {"http://",
        {"http", NULL, NULL, NULL, NULL, "//", NULL, NULL}},
    {"/path",
        {NULL, NULL, NULL, NULL, NULL, "/path", NULL, NULL}},
    {"://",
        {"", NULL, NULL, NULL, NULL, "//", NULL, NULL}},
    {"",
        {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}},
    {"http://user@host.com",
        {"http", "user", NULL, "host.com", NULL, "", NULL, NULL}},
    {NULL,
        { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }}
};

TEST(UtilTest, HtpParseUri) {
    bstr *input = NULL;
    htp_uri_t *uri = NULL;
    uri_test *test;

    input = bstr_dup_c("");
    EXPECT_EQ(HTP_OK, htp_parse_uri(input, &uri));
    bstr_free(input);
    free_htp_uri_t(&uri);

    test = uri_tests;
    while (test->uri != NULL) {
        input = bstr_dup_c(test->uri);
        EXPECT_EQ(HTP_OK, htp_parse_uri(input, &uri));
        EXPECT_PRED_FORMAT2(UriIsExpected, test->expected, uri)
                << "Failed URI = " << test->uri << std::endl;

        bstr_free(input);
        free_htp_uri_t(&uri);
        ++test;
    }
}

TEST(UtilTest, ParseHostPort1) {
    bstr *i = bstr_dup_c("www.example.com");
    bstr *host;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(bstr_cmp(i, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(0, flag);

    bstr_free(host);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort2) {
    bstr *i = bstr_dup_c(" www.example.com ");
    bstr *e = bstr_dup_c("www.example.com");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(0, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort3) {
    bstr *i = bstr_dup_c(" www.example.com:8001 ");
    bstr *e = bstr_dup_c("www.example.com");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(8001, port);
    ASSERT_EQ(0, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort4) {
    bstr *i = bstr_dup_c(" www.example.com :  8001 ");
    bstr *e = bstr_dup_c("www.example.com");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(8001, port);
    ASSERT_EQ(0, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort5) {
    bstr *i = bstr_dup_c("www.example.com.");
    bstr *e = bstr_dup_c("www.example.com.");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(0, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort6) {
    bstr *i = bstr_dup_c("www.example.com.:8001");
    bstr *e = bstr_dup_c("www.example.com.");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(8001, port);
    ASSERT_EQ(0, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort7) {
    bstr *i = bstr_dup_c("www.example.com:");
    bstr *e = bstr_dup_c("www.example.com");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(1, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort8) {
    bstr *i = bstr_dup_c("www.example.com:ff");
    bstr *e = bstr_dup_c("www.example.com");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(1, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort9) {
    bstr *i = bstr_dup_c("www.example.com:0");
    bstr *e = bstr_dup_c("www.example.com");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(1, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort10) {
    bstr *i = bstr_dup_c("www.example.com:65536");
    bstr *e = bstr_dup_c("www.example.com");
    bstr *host = NULL;
    int port;
    int flag = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &flag));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(1, flag);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort11) {
    bstr *i = bstr_dup_c("[::1]:8080");
    bstr *e = bstr_dup_c("[::1]");
    bstr *host = NULL;
    int port;
    int invalid = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &invalid));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(8080, port);
    ASSERT_EQ(0, invalid);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort12) {
    bstr *i = bstr_dup_c("[::1]:");
    bstr *e = bstr_dup_c("[::1]");
    bstr *host = NULL;
    int port;
    int invalid = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &invalid));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(1, invalid);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort13) {
    bstr *i = bstr_dup_c("[::1]x");
    bstr *e = bstr_dup_c("[::1]");
    bstr *host = NULL;
    int port;
    int invalid = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &invalid));

    ASSERT_TRUE(host != NULL);
    ASSERT_TRUE(bstr_cmp(e, host) == 0);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(1, invalid);

    bstr_free(host);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseHostPort14) {
    bstr *i = bstr_dup_c("[::1");
    bstr *host = NULL;
    int port;
    int invalid = 0;

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, NULL, &port, &invalid));

    ASSERT_TRUE(host == NULL);
    ASSERT_EQ(-1, port);
    ASSERT_EQ(1, invalid);

    bstr_free(host);
    bstr_free(i);
}

TEST(UtilTest, ParseContentType1) {
    bstr *i = bstr_dup_c("multipart/form-data");
    bstr *e = bstr_dup_c("multipart/form-data");
    bstr *ct = NULL;

    ASSERT_EQ(HTP_OK, htp_parse_ct_header(i, &ct));

    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(bstr_cmp(e, ct) == 0);

    bstr_free(ct);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseContentType2) {
    bstr *i = bstr_dup_c("multipart/form-data;boundary=X");
    bstr *e = bstr_dup_c("multipart/form-data");
    bstr *ct = NULL;

    ASSERT_EQ(HTP_OK, htp_parse_ct_header(i, &ct));

    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(bstr_cmp(e, ct) == 0);

    bstr_free(ct);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseContentType3) {
    bstr *i = bstr_dup_c("multipart/form-data boundary=X");
    bstr *e = bstr_dup_c("multipart/form-data");
    bstr *ct = NULL;

    ASSERT_EQ(HTP_OK, htp_parse_ct_header(i, &ct));

    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(bstr_cmp(e, ct) == 0);

    bstr_free(ct);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseContentType4) {
    bstr *i = bstr_dup_c("multipart/form-data,boundary=X");
    bstr *e = bstr_dup_c("multipart/form-data");
    bstr *ct = NULL;

    ASSERT_EQ(HTP_OK, htp_parse_ct_header(i, &ct));

    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(bstr_cmp(e, ct) == 0);

    bstr_free(ct);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseContentType5) {
    bstr *i = bstr_dup_c("multipart/FoRm-data");
    bstr *e = bstr_dup_c("multipart/form-data");
    bstr *ct = NULL;

    ASSERT_EQ(HTP_OK, htp_parse_ct_header(i, &ct));

    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(bstr_cmp(e, ct) == 0);

    bstr_free(ct);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ParseContentType6) {
    bstr *i = bstr_dup_c("multipart/form-data\t boundary=X");
    bstr *e = bstr_dup_c("multipart/form-data\t");
    bstr *ct = NULL;

    ASSERT_EQ(HTP_OK, htp_parse_ct_header(i, &ct));

    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(bstr_cmp(e, ct) == 0);

    bstr_free(ct);
    bstr_free(e);
    bstr_free(i);
}

TEST(UtilTest, ValidateHostname1) {
    bstr *i = bstr_dup_c("www.example.com");
    ASSERT_EQ(1, htp_validate_hostname(i));
    bstr_free(i);
}

TEST(UtilTest, ValidateHostname2) {
    bstr *i = bstr_dup_c(".www.example.com");
    ASSERT_EQ(0, htp_validate_hostname(i));
    bstr_free(i);
}

TEST(UtilTest, ValidateHostname3) {
    bstr *i = bstr_dup_c("www..example.com");
    ASSERT_EQ(0, htp_validate_hostname(i));
    bstr_free(i);
}

TEST(UtilTest, ValidateHostname4) {
    bstr *i = bstr_dup_c("www.example.com..");
    ASSERT_EQ(0, htp_validate_hostname(i));
    bstr_free(i);
}

TEST(UtilTest, ValidateHostname5) {
    bstr *i = bstr_dup_c("www example com");
    ASSERT_EQ(0, htp_validate_hostname(i));
    bstr_free(i);
}

TEST(UtilTest, ValidateHostname6) {
    bstr *i = bstr_dup_c("");
    ASSERT_EQ(0, htp_validate_hostname(i));
    bstr_free(i);
}

TEST(UtilTest, ValidateHostname7) {
    // Label over 63 characters.
    bstr *i = bstr_dup_c("www.exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.com");
    ASSERT_EQ(0, htp_validate_hostname(i));
    bstr_free(i);
}

TEST(UtilTest, ValidateHostname8) {
    bstr *i = bstr_dup_c("www.ExAmplE-1984.com");
    ASSERT_EQ(1, htp_validate_hostname(i));
    bstr_free(i);
}

class DecodingTest : public testing::Test {
protected:

    virtual void SetUp() {
        testing::Test::SetUp();

        cfg = htp_config_create();
        connp = htp_connp_create(cfg);
        htp_connp_open(connp, "127.0.0.1", 32768, "127.0.0.1", 80, NULL);
        tx = htp_connp_tx_create(connp);
    }

    virtual void TearDown() {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);

        testing::Test::TearDown();
    }

    htp_connp_t *connp;

    htp_cfg_t *cfg;

    htp_tx_t *tx;
};

TEST_F(DecodingTest, DecodeUrlencodedInplace1_Identity) {
    bstr *i = bstr_dup_c("/dest");
    bstr *e = bstr_dup_c("/dest");
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace2_Urlencoded) {
    bstr *i = bstr_dup_c("/%64est");
    bstr *e = bstr_dup_c("/dest");
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace3_UrlencodedInvalidPreserve) {
    bstr *i = bstr_dup_c("/%xxest");
    bstr *e = bstr_dup_c("/%xxest");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace4_UrlencodedInvalidRemove) {
    bstr *i = bstr_dup_c("/%xxest");
    bstr *e = bstr_dup_c("/xxest");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_REMOVE_PERCENT);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace5_UrlencodedInvalidDecode) {
    bstr *i = bstr_dup_c("/%}9est");
    bstr *e = bstr_dup_c("/iest");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace6_UrlencodedInvalidNotEnoughBytes) {
    bstr *i = bstr_dup_c("/%a");
    bstr *e = bstr_dup_c("/%a");
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace7_UrlencodedInvalidNotEnoughBytes) {
    bstr *i = bstr_dup_c("/%");
    bstr *e = bstr_dup_c("/%");
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace8_Uencoded) {
    bstr *i = bstr_dup_c("/%u0064");
    bstr *e = bstr_dup_c("/d");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace9_UencodedDoNotDecode) {
    bstr *i = bstr_dup_c("/%u0064");
    bstr *e = bstr_dup_c("/%u0064");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 0);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace10_UencodedInvalidNotEnoughBytes) {
    bstr *i = bstr_dup_c("/%u006");
    bstr *e = bstr_dup_c("/%u006");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace11_UencodedInvalidPreserve) {
    bstr *i = bstr_dup_c("/%u006");
    bstr *e = bstr_dup_c("/%u006");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace12_UencodedInvalidRemove) {
    bstr *i = bstr_dup_c("/%uXXXX");
    bstr *e = bstr_dup_c("/uXXXX");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_REMOVE_PERCENT);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace13_UencodedInvalidDecode) {
    bstr *i = bstr_dup_c("/%u00}9");
    bstr *e = bstr_dup_c("/i");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace14_UencodedInvalidPreserve) {
    bstr *i = bstr_dup_c("/%u00");
    bstr *e = bstr_dup_c("/%u00");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace15_UencodedInvalidPreserve) {
    bstr *i = bstr_dup_c("/%u0");
    bstr *e = bstr_dup_c("/%u0");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace16_UencodedInvalidPreserve) {
    bstr *i = bstr_dup_c("/%u");
    bstr *e = bstr_dup_c("/%u");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace17_UrlencodedNul) {
    bstr *i = bstr_dup_c("/%00");
    bstr *e = bstr_dup_mem("/\0", 2);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace18_UrlencodedNulTerminates) {
    bstr *i = bstr_dup_c("/%00ABC");
    bstr *e = bstr_dup_c("/");
    htp_config_set_nul_encoded_terminates(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace19_RawNulTerminates) {
    bstr *i = bstr_dup_mem("/\0ABC", 5);
    bstr *e = bstr_dup_c("/");
    htp_config_set_nul_raw_terminates(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodeUrlencodedInplace20_UencodedBestFit) {
    bstr *i = bstr_dup_c("/%u0107");
    bstr *e = bstr_dup_c("/c");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_tx_urldecode_params_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace1_UrlencodedInvalidNotEnoughBytes) {
    bstr *i = bstr_dup_c("/%a");
    bstr *e = bstr_dup_c("/%a");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace2_UencodedInvalidNotEnoughBytes) {
    bstr *i = bstr_dup_c("/%uX");
    bstr *e = bstr_dup_c("/%uX");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace3_UencodedValid) {
    bstr *i = bstr_dup_c("/%u0107");
    bstr *e = bstr_dup_c("/c");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace4_UencodedInvalidNotHexDigits_Remove) {
    bstr *i = bstr_dup_c("/%uXXXX");
    bstr *e = bstr_dup_c("/uXXXX");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_REMOVE_PERCENT);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace5_UencodedInvalidNotHexDigits_Preserve) {
    bstr *i = bstr_dup_c("/%uXXXX");
    bstr *e = bstr_dup_c("/%uXXXX");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace6_UencodedInvalidNotHexDigits_Process) {
    bstr *i = bstr_dup_c("/%u00}9");
    bstr *e = bstr_dup_c("/i");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace7_UencodedNul) {
    bstr *i = bstr_dup_c("/%u0000");
    bstr *e = bstr_dup_mem("/\0", 2);
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_ENCODED_NUL);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace8_UencodedNotEnough_Remove) {
    bstr *i = bstr_dup_c("/%uXXX");
    bstr *e = bstr_dup_c("/uXXX");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_REMOVE_PERCENT);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace9_UencodedNotEnough_Preserve) {
    bstr *i = bstr_dup_c("/%uXXX");
    bstr *e = bstr_dup_c("/%uXXX");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace10_UrlencodedNul) {
    bstr *i = bstr_dup_c("/%00123");
    bstr *e = bstr_dup_mem("/\000123", 5);
    htp_decode_path_inplace(tx, i);    
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_ENCODED_NUL);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace11_UrlencodedNul_Terminates) {
    bstr *i = bstr_dup_c("/%00123");
    bstr *e = bstr_dup_mem("/", 1);
    htp_config_set_nul_encoded_terminates(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_decode_path_inplace(tx, i);    
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_ENCODED_NUL);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace12_EncodedSlash) {
    bstr *i = bstr_dup_c("/one%2ftwo");
    bstr *e = bstr_dup_c("/one%2ftwo");
    htp_config_set_path_separators_decode(cfg, HTP_DECODER_DEFAULTS, 0);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_ENCODED_SEPARATOR);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace13_EncodedSlash_Decode) {
    bstr *i = bstr_dup_c("/one%2ftwo");
    bstr *e = bstr_dup_c("/one/two");
    htp_config_set_path_separators_decode(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_ENCODED_SEPARATOR);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace14_Urlencoded_Invalid_Preserve) {
    bstr *i = bstr_dup_c("/%HH");
    bstr *e = bstr_dup_c("/%HH");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace15_Urlencoded_Invalid_Remove) {
    bstr *i = bstr_dup_c("/%HH");
    bstr *e = bstr_dup_c("/HH");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_REMOVE_PERCENT);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace16_Urlencoded_Invalid_Process) {
    bstr *i = bstr_dup_c("/%}9");
    bstr *e = bstr_dup_c("/i");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace17_Urlencoded_NotEnough_Remove) {
    bstr *i = bstr_dup_c("/%H");
    bstr *e = bstr_dup_c("/H");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_REMOVE_PERCENT);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace18_Urlencoded_NotEnough_Preserve) {
    bstr *i = bstr_dup_c("/%H");
    bstr *e = bstr_dup_c("/%H");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace19_Urlencoded_NotEnough_Process) {
    bstr *i = bstr_dup_c("/%H");
    bstr *e = bstr_dup_c("/%H");
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_DEFAULTS, HTP_URL_DECODE_PROCESS_INVALID);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    ASSERT_TRUE(tx->flags & HTP_PATH_INVALID_ENCODING);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace20_RawNul1) {
    bstr *i = bstr_dup_mem("/\000123", 5);
    bstr *e = bstr_dup_c("/");
    htp_config_set_nul_raw_terminates(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);    
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace21_RawNul1) {
    bstr *i = bstr_dup_mem("/\000123", 5);
    bstr *e = bstr_dup_mem("/\000123", 5);
    htp_config_set_nul_raw_terminates(cfg, HTP_DECODER_DEFAULTS, 0);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace22_ConvertBackslash1) {
    bstr *i = bstr_dup_c("/one\\two");
    bstr *e = bstr_dup_c("/one/two");
    htp_config_set_backslash_convert_slashes(cfg, HTP_DECODER_DEFAULTS, 1);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, DecodePathInplace23_ConvertBackslash2) {
    bstr *i = bstr_dup_c("/one\\two");
    bstr *e = bstr_dup_c("/one\\two");
    htp_config_set_backslash_convert_slashes(cfg, HTP_DECODER_DEFAULTS, 0);
    htp_decode_path_inplace(tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

TEST_F(DecodingTest, InvalidUtf8) {
    bstr *i = bstr_dup_c("\xf1.");
    bstr *e = bstr_dup_c("?.");
    htp_config_set_utf8_convert_bestfit(cfg, HTP_DECODER_URL_PATH, 1);
    htp_utf8_decode_path_inplace(cfg, tx, i);
    ASSERT_TRUE(bstr_cmp(i, e) == 0);
    bstr_free(e);
    bstr_free(i);
}

class UrlencodedParser : public testing::Test {
protected:

    virtual void SetUp() {
        cfg = htp_config_create();
        connp = htp_connp_create(cfg);
        htp_connp_open(connp, "127.0.0.1", 32768, "127.0.0.1", 80, NULL);
        tx = htp_connp_tx_create(connp);
        urlenp = htp_urlenp_create(tx);
    }

    virtual void TearDown() {
        htp_urlenp_destroy(urlenp);
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
    }

    htp_connp_t *connp;

    htp_cfg_t *cfg;

    htp_tx_t *tx;

    htp_urlenp_t *urlenp;
};

TEST_F(UrlencodedParser, Empty) {
    htp_urlenp_parse_complete(urlenp, "", 0);

    ASSERT_EQ(0, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, EmptyKey1) {
    htp_urlenp_parse_complete(urlenp, "&", 1);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "", 0);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, EmptyKey2) {
    htp_urlenp_parse_complete(urlenp, "=&", 2);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "", 0);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, EmptyKey3) {
    htp_urlenp_parse_complete(urlenp, "=1&", 3);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "", 0);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p, "1"));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, EmptyKeyAndValue) {
    htp_urlenp_parse_complete(urlenp, "=", 1);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "", 0);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, OnePairEmptyValue) {
    htp_urlenp_parse_complete(urlenp, "p=", 2);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, OnePair) {
    htp_urlenp_parse_complete(urlenp, "p=1", 3);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p, "1"));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, TwoPairs) {
    htp_urlenp_parse_complete(urlenp, "p=1&q=2", 7);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, bstr_cmp_c(p, "1"));

    bstr *q = (bstr *) htp_table_get_mem(urlenp->params, "q", 1);
    ASSERT_TRUE(q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(q, "2"));

    ASSERT_EQ(2, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, KeyNoValue1) {
    htp_urlenp_parse_complete(urlenp, "p", 1);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, KeyNoValue2) {
    htp_urlenp_parse_complete(urlenp, "p&", 2);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, KeyNoValue3) {
    htp_urlenp_parse_complete(urlenp, "p&q", 3);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    bstr *q = (bstr *) htp_table_get_mem(urlenp->params, "q", 1);
    ASSERT_TRUE(q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(q, ""));

    ASSERT_EQ(2, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, KeyNoValue4) {
    htp_urlenp_parse_complete(urlenp, "p&q=2", 5);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    bstr *q = (bstr *) htp_table_get_mem(urlenp->params, "q", 1);
    ASSERT_TRUE(q != NULL);
    ASSERT_EQ(0, bstr_cmp_c(q, "2"));

    ASSERT_EQ(2, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, Partial1) {
    htp_urlenp_parse_partial(urlenp, "p", 1);
    htp_urlenp_finalize(urlenp);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, Partial2) {
    htp_urlenp_parse_partial(urlenp, "p", 1);
    htp_urlenp_parse_partial(urlenp, "x", 1);
    htp_urlenp_finalize(urlenp);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "px", 2);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, Partial3) {
    htp_urlenp_parse_partial(urlenp, "p", 1);
    htp_urlenp_parse_partial(urlenp, "x&", 2);
    htp_urlenp_finalize(urlenp);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "px", 2);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, Partial4) {
    htp_urlenp_parse_partial(urlenp, "p", 1);
    htp_urlenp_parse_partial(urlenp, "=", 1);
    htp_urlenp_finalize(urlenp);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, Partial5) {
    htp_urlenp_parse_partial(urlenp, "p", 1);
    htp_urlenp_parse_partial(urlenp, "", 0);
    htp_urlenp_parse_partial(urlenp, "", 0);
    htp_urlenp_parse_partial(urlenp, "", 0);
    htp_urlenp_finalize(urlenp);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "p", 1);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, ""));

    ASSERT_EQ(1, htp_table_size(urlenp->params));
}

TEST_F(UrlencodedParser, Partial6) {
    htp_urlenp_parse_partial(urlenp, "px", 2);
    htp_urlenp_parse_partial(urlenp, "n", 1);
    htp_urlenp_parse_partial(urlenp, "", 0);
    htp_urlenp_parse_partial(urlenp, "=", 1);
    htp_urlenp_parse_partial(urlenp, "1", 1);
    htp_urlenp_parse_partial(urlenp, "2", 1);
    htp_urlenp_parse_partial(urlenp, "&", 1);
    htp_urlenp_parse_partial(urlenp, "qz", 2);
    htp_urlenp_parse_partial(urlenp, "n", 1);
    htp_urlenp_parse_partial(urlenp, "", 0);
    htp_urlenp_parse_partial(urlenp, "=", 1);
    htp_urlenp_parse_partial(urlenp, "2", 1);
    htp_urlenp_parse_partial(urlenp, "3", 1);
    htp_urlenp_parse_partial(urlenp, "&", 1);
    htp_urlenp_finalize(urlenp);

    bstr *p = (bstr *) htp_table_get_mem(urlenp->params, "pxn", 3);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(p, "12"));

    bstr *q = (bstr *) htp_table_get_mem(urlenp->params, "qzn", 3);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(0, bstr_cmp_c(q, "23"));

    ASSERT_EQ(2, htp_table_size(urlenp->params));
}

TEST(List, Misc) {
    htp_list_t *l = htp_list_create(16);

    htp_list_push(l, (void *) "1");
    htp_list_push(l, (void *) "2");
    htp_list_push(l, (void *) "3");

    ASSERT_EQ(3, htp_list_size(l));

    char *p = (char *) htp_list_pop(l);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("3", p));

    ASSERT_EQ(2, htp_list_size(l));

    p = (char *) htp_list_shift(l);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("1", p));

    ASSERT_EQ(1, htp_list_size(l));

    p = (char *) htp_list_shift(l);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("2", p));

    p = (char *) htp_list_shift(l);
    ASSERT_TRUE(p == NULL);

    p = (char *) htp_list_pop(l);
    ASSERT_TRUE(p == NULL);

    htp_list_destroy(l);
}

TEST(List, Misc2) {
    htp_list_t *l = htp_list_create(1);

    htp_list_push(l, (void *) "1");

    char *p = (char *) htp_list_shift(l);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("1", p));

    htp_list_push(l, (void *) "2");

    p = (char *) htp_list_shift(l);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("2", p));

    ASSERT_EQ(0, htp_list_size(l));

    htp_list_destroy(l);
}

TEST(List, Misc3) {
    htp_list_t *l = htp_list_create(2);

    htp_list_push(l, (void *) "1");
    htp_list_push(l, (void *) "2");

    char *p = (char *) htp_list_shift(l);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("1", p));

    htp_list_push(l, (void *) "3");

    p = (char *) htp_list_get(l, 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("3", p));

    ASSERT_EQ(2, htp_list_size(l));

    htp_list_replace(l, 1, (void *) "4");

    p = (char *) htp_list_pop(l);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("4", p));

    htp_list_destroy(l);
}

TEST(List, Expand1) {
    htp_list_t *l = htp_list_create(2);

    htp_list_push(l, (void *) "1");
    htp_list_push(l, (void *) "2");

    ASSERT_EQ(2, htp_list_size(l));

    htp_list_push(l, (void *) "3");

    ASSERT_EQ(3, htp_list_size(l));

    char *p = (char *) htp_list_get(l, 0);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("1", p));

    p = (char *) htp_list_get(l, 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("2", p));

    p = (char *) htp_list_get(l, 2);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("3", p));

    htp_list_destroy(l);
}

TEST(List, Expand2) {
    htp_list_t *l = htp_list_create(2);

    htp_list_push(l, (void *) "1");
    htp_list_push(l, (void *) "2");

    ASSERT_EQ(2, htp_list_size(l));

    htp_list_shift(l);

    ASSERT_EQ(1, htp_list_size(l));

    htp_list_push(l, (void *) "3");
    htp_list_push(l, (void *) "4");

    ASSERT_EQ(3, htp_list_size(l));

    char *p = (char *) htp_list_get(l, 0);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("2", p));

    p = (char *) htp_list_get(l, 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("3", p));

    p = (char *) htp_list_get(l, 2);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("4", p));

    htp_list_destroy(l);
}

TEST(Table, Misc) {
    htp_table_t *t = htp_table_create(2);

    bstr *pkey = bstr_dup_c("p");
    bstr *qkey = bstr_dup_c("q");

    htp_table_addk(t, pkey, "1");
    htp_table_addk(t, qkey, "2");

    char *p = (char *) htp_table_get_mem(t, "z", 1);
    ASSERT_TRUE(p == NULL);

    p = (char *) htp_table_get(t, pkey);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(0, strcmp("1", p));

    htp_table_clear_ex(t);

    bstr_free(qkey);
    bstr_free(pkey);

    htp_table_destroy(t);
}

TEST(Util, ExtractQuotedString) {
    bstr *s;
    size_t end_offset;

    htp_status_t rc = htp_extract_quoted_string_as_bstr((unsigned char *) "\"test\"", 6, &s, &end_offset);
    ASSERT_EQ(HTP_OK, rc);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(0, bstr_cmp_c(s, "test"));
    ASSERT_EQ(5, end_offset);
    bstr_free(s);

    rc = htp_extract_quoted_string_as_bstr((unsigned char *) "\"te\\\"st\"", 8, &s, &end_offset);
    ASSERT_EQ(HTP_OK, rc);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(0, bstr_cmp_c(s, "te\"st"));
    ASSERT_EQ(7, end_offset);
    bstr_free(s);
}

TEST(Util, NormalizeUriPath) {
    bstr *s = NULL;

    s = bstr_dup_c("/a/b/c/./../../g");
    htp_normalize_uri_path_inplace(s);
    ASSERT_EQ(0, bstr_cmp_c(s, "/a/g"));
    bstr_free(s);

    s = bstr_dup_c("mid/content=5/../6");
    htp_normalize_uri_path_inplace(s);
    ASSERT_EQ(0, bstr_cmp_c(s, "mid/6"));
    bstr_free(s);

    s = bstr_dup_c("./one");
    htp_normalize_uri_path_inplace(s);    
    ASSERT_EQ(0, bstr_cmp_c(s, "one"));
    bstr_free(s);
    
    s = bstr_dup_c("../one");
    htp_normalize_uri_path_inplace(s);    
    ASSERT_EQ(0, bstr_cmp_c(s, "one"));
    bstr_free(s);

    s = bstr_dup_c(".");
    htp_normalize_uri_path_inplace(s);    
    ASSERT_EQ(0, bstr_cmp_c(s, ""));
    bstr_free(s);

    s = bstr_dup_c("..");
    htp_normalize_uri_path_inplace(s);    
    ASSERT_EQ(0, bstr_cmp_c(s, ""));
    bstr_free(s);
    
    s = bstr_dup_c("one/.");
    htp_normalize_uri_path_inplace(s);    
    ASSERT_EQ(0, bstr_cmp_c(s, "one"));
    bstr_free(s);
    
    s = bstr_dup_c("one/..");
    htp_normalize_uri_path_inplace(s);    
    ASSERT_EQ(0, bstr_cmp_c(s, ""));
    bstr_free(s);

    s = bstr_dup_c("one/../");
    htp_normalize_uri_path_inplace(s);    
    ASSERT_EQ(0, bstr_cmp_c(s, ""));
    bstr_free(s);    
}

TEST_F(UrlencodedParser, UrlDecode1) {
    bstr *s = NULL;
    uint64_t flags;
    
    s = bstr_dup_c("/one/tw%u006f/three/%u123");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URLENCODED, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URLENCODED, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_urldecode_inplace(cfg, HTP_DECODER_URLENCODED, s, &flags);
    ASSERT_EQ(0, bstr_cmp_c(s, "/one/two/three/%u123"));
    bstr_free(s);

    s = bstr_dup_c("/one/tw%u006f/three/%uXXXX");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URLENCODED, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URLENCODED, HTP_URL_DECODE_PRESERVE_PERCENT);
    htp_urldecode_inplace(cfg, HTP_DECODER_URLENCODED, s, &flags);
    ASSERT_EQ(0, bstr_cmp_c(s, "/one/two/three/%uXXXX"));
    bstr_free(s);

    s = bstr_dup_c("/one/tw%u006f/three/%u123");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URLENCODED, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URLENCODED, HTP_URL_DECODE_REMOVE_PERCENT);
    htp_urldecode_inplace(cfg, HTP_DECODER_URLENCODED, s, &flags);
    ASSERT_EQ(0, bstr_cmp_c(s, "/one/two/three/u123"));
    bstr_free(s);

    s = bstr_dup_c("/one/tw%u006f/three/%3");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URLENCODED, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URLENCODED, HTP_URL_DECODE_REMOVE_PERCENT);
    htp_urldecode_inplace(cfg, HTP_DECODER_URLENCODED, s, &flags);
    ASSERT_EQ(0, bstr_cmp_c(s, "/one/two/three/3"));
    bstr_free(s);

    s = bstr_dup_c("/one/tw%u006f/three/%3");
    htp_config_set_u_encoding_decode(cfg, HTP_DECODER_URLENCODED, 1);
    htp_config_set_url_encoding_invalid_handling(cfg, HTP_DECODER_URLENCODED, HTP_URL_DECODE_PROCESS_INVALID);
    htp_urldecode_inplace(cfg, HTP_DECODER_URLENCODED, s, &flags);
    ASSERT_EQ(0, bstr_cmp_c(s, "/one/two/three/%3"));
    bstr_free(s);
}
