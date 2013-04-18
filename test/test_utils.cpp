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
    result = htp_chomp((unsigned char*) data, &len);
    EXPECT_EQ(2, result);
    EXPECT_EQ(4, len);

    strcpy(data, "foo\n");
    len = strlen(data);
    result = htp_chomp((unsigned char*) data, &len);
    EXPECT_EQ(1, result);
    EXPECT_EQ(3, len);

    strcpy(data, "arfarf");
    len = strlen(data);
    result = htp_chomp((unsigned char*) data, &len);
    EXPECT_EQ(0, result);
    EXPECT_EQ(6, len);
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
        {}}
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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &flag));

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &invalid));   

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &invalid));   

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &invalid));   

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

    ASSERT_EQ(HTP_OK, htp_parse_hostport(i, &host, &port, &invalid));   

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
