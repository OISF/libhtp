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
 * @brief Test for the bstr code.
 *
 * @author Craig Forbes <cforbes@qualys.com>
 */

#include <iostream>
#include <gtest/gtest.h>
#include <htp/htp_private.h>

TEST(BstrTest, Alloc) {
    bstr *p1;
    p1 = bstr_alloc(10);
    EXPECT_EQ(10, bstr_size(p1));
    EXPECT_EQ(0, bstr_len(p1));
    bstr_free(p1);
}

TEST(BstrTest, ExpandLocal) {
    bstr *p1;
    bstr *p2;

    p1 = bstr_alloc(10);
    p2 = bstr_expand(p1, 100);
    ASSERT_NE((void *)NULL, p2);
    EXPECT_EQ(100, bstr_size(p2));
    EXPECT_EQ(0, bstr_len(p2));

    bstr_free(p2);
}

TEST(BstrTest, ExpandSmaller) {
    bstr *p1;
    bstr *p2;

    p1 = bstr_alloc(100);
    p2 = bstr_expand(p1, 10);
    ASSERT_TRUE(p2 == NULL);

    bstr_free(p1);
}

TEST(BstrTest, ExpandPtr) {
    bstr *b;
    b = (bstr*) malloc(sizeof(bstr));
    ASSERT_NE((bstr*)NULL, b);
    b->realptr = (unsigned char*) malloc(10);
    b->len = 0;
    b->size = 10;
    ASSERT_NE((unsigned char*)NULL, bstr_ptr(b));

    bstr *p2 = bstr_expand(b, 100);
    EXPECT_TRUE(p2 == NULL);

    free(b->realptr);
    bstr_free(b);
}

/*
// For the time being, expansion is not allowed
// when data is externally stored. This feature
// is currently only used when wrapping existing
// memory areas.
TEST(BstrTest, ExpandPtr) {
    bstr *b;
    b = (bstr*) malloc(sizeof(bstr));
    ASSERT_NE((bstr*)NULL, b);
    b->ptr = (unsigned char*) malloc(10);
    b->len = 0;
    b->size = 10;
    ASSERT_NE((unsigned char*)NULL, bstr_ptr(b));

    bstr *p2;
    p2 = bstr_expand(b, 100);
    EXPECT_TRUE(p2 != NULL);
    EXPECT_EQ(100, bstr_size(p2));
    EXPECT_EQ(0, bstr_len(p2));

    free(p2->ptr);
    bstr_free(p2);
}
*/

TEST(BstrTest, DupC) {
    bstr *p1;
    p1 = bstr_dup_c("arfarf");

    EXPECT_EQ(6, bstr_size(p1));
    EXPECT_EQ(6, bstr_len(p1));
    EXPECT_EQ(0, memcmp("arfarf", bstr_ptr(p1), 6));

    bstr_free(p1);
}

TEST(BstrTest, DupStr) {
    bstr *p1;
    bstr *p2;
    p1 = bstr_dup_c("s0123456789abcdefghijklmnopqrstuvwxyz");
    p2 = bstr_dup(p1);

    EXPECT_EQ(bstr_len(p1), bstr_len(p2));
    EXPECT_EQ(0, memcmp(bstr_ptr(p1), bstr_ptr(p2), bstr_len(p1)));

    bstr_free(p1);
    bstr_free(p2);
}

TEST(BstrTest, DupBin) {
    bstr *src = bstr_dup_mem("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20);
    bstr *dst;
    dst = bstr_dup(src);

    EXPECT_EQ(bstr_len(src), bstr_len(dst));
    EXPECT_EQ(0, memcmp(bstr_ptr(src), bstr_ptr(dst), bstr_len(src)));

    bstr_free(src);
    bstr_free(dst);
}

TEST(BstrTest, DupEx) {
    bstr *p1;
    bstr *p2;
    p1 = bstr_dup_c("0123456789abcdefghijkl");
    p2 = bstr_dup_ex(p1, 4, 10);

    EXPECT_EQ(10, bstr_size(p2));
    EXPECT_EQ(10, bstr_len(p2));
    EXPECT_EQ(0, memcmp("456789abcd", bstr_ptr(p2),10));

    bstr_free(p1);
    bstr_free(p2);
}

TEST(BstrTest, DupMem) {
    bstr *dst;
    dst = bstr_dup_mem("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 18);
    EXPECT_EQ(0, memcmp("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", bstr_ptr(dst), 18));

    bstr_free(dst);
}

TEST(BstrTest, DupLower) {
    bstr *p1;
    bstr *p2;
    p1 = bstr_dup_c("0123456789ABCDEFGhIJKL");
    p2 = bstr_dup_lower(p1);

    EXPECT_EQ(0, memcmp("0123456789abcdefghijkl", bstr_ptr(p2), 22));

    bstr_free(p1);
    bstr_free(p2);
}

TEST(BstrTest, ChrRchr) {
    bstr *p1 = bstr_dup_c("0123456789abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(13, bstr_chr(p1, 'd'));
    EXPECT_EQ(-1, bstr_chr(p1, '?'));
    EXPECT_EQ(13, bstr_chr(p1, 'd'));
    EXPECT_EQ(-1, bstr_chr(p1, '?'));

    bstr_free(p1);
}

TEST(BstrTest, Cmp) {
    bstr *p1;
    bstr *p2;
    bstr *p3;
    bstr *p4;
    p1 = bstr_dup_c("arfarf");
    p2 = bstr_dup_c("arfarf");
    p3 = bstr_dup_c("arfArf");
    p4 = bstr_dup_c("arfarf2");

    EXPECT_EQ(0, bstr_cmp(p1,p1));
    EXPECT_EQ(0, bstr_cmp(p1,p2));
    EXPECT_EQ(0, bstr_cmp(p2,p1));
    EXPECT_EQ(1, bstr_cmp(p1,p3));
    EXPECT_EQ(-1, bstr_cmp(p3,p1));
    EXPECT_EQ(-1, bstr_cmp(p1,p4));
    EXPECT_EQ(1, bstr_cmp(p4,p1));

    bstr_free(p1);
    bstr_free(p2);
    bstr_free(p3);
    bstr_free(p4);
}

TEST(BstrTest, CmpNocase) {
    bstr *p1;
    bstr *p2;
    bstr *p3;
    p1 = bstr_dup_c("arfarf");
    p2 = bstr_dup_c("arfarf");
    p3 = bstr_dup_c("arfArf");

    EXPECT_EQ(0, bstr_cmp_nocase(p1,p1));
    EXPECT_EQ(0, bstr_cmp_nocase(p1,p2));
    EXPECT_EQ(0, bstr_cmp_nocase(p2,p1));
    EXPECT_EQ(0, bstr_cmp_nocase(p1,p3));
    EXPECT_EQ(0, bstr_cmp_nocase(p3,p1));

    bstr_free(p1);
    bstr_free(p2);
    bstr_free(p3);
}

TEST(BstrTest, CmpC) {
    bstr *p1;
    p1 = bstr_dup_c("arfarf");
    EXPECT_EQ(0, bstr_cmp_c(p1, "arfarf"));
    EXPECT_EQ(-1, bstr_cmp_c(p1, "arfarf2"));
    EXPECT_EQ(1, bstr_cmp_c(p1, "arf"));
    EXPECT_EQ(-1, bstr_cmp_c(p1, "not equal"));

    bstr_free(p1);
}

TEST(BstrTest, CmpCNocase) {
    bstr *p1;
    p1 = bstr_dup_c("arfarf");
    EXPECT_EQ(0, bstr_cmp_c_nocase(p1, "arfarf"));
    EXPECT_EQ(0, bstr_cmp_c_nocase(p1, "arfARF"));
    EXPECT_EQ(1, bstr_cmp_c_nocase(p1, "ArF"));
    EXPECT_EQ(-1, bstr_cmp_c_nocase(p1, "Not equal"));

    bstr_free(p1);
}

TEST(BstrTest, CmpEx) {
    const char *s1 = "arfarf12345";
    const char *s2 = "arfarF2345";

    EXPECT_EQ(0, bstr_util_cmp_mem(s1, 5, s2, 5));
    EXPECT_EQ(1, bstr_util_cmp_mem(s1, 6, s2, 6));
    EXPECT_EQ(1, bstr_util_cmp_mem(s1, 5, s2, 4));
    EXPECT_EQ(-1, bstr_util_cmp_mem(s2, 4, s1, 5));
}

TEST(BstrTest, CmpNocaseEx) {
    const char *s1 = "arfarf12345";
    const char *s2 = "arfarF2345";

    EXPECT_EQ(0, bstr_util_cmp_mem_nocase(s1, 6, s2, 6));
    EXPECT_EQ(1, bstr_util_cmp_mem_nocase(s1, 6, s2, 5));
    EXPECT_EQ(-1, bstr_util_cmp_mem_nocase(s2, 5, s1, 6));
}

TEST(BstrTest, CmpMem) {
    bstr *s = bstr_dup_c("arfArf");
    EXPECT_EQ(0, bstr_cmp_mem(s, "arfArf", 6));
    bstr_free(s);
}

TEST(BstrTest, ToLowercase) {
    bstr *p1;
    bstr *p2;
    p1 = bstr_dup_c("aRf3ArF");
    p2 = bstr_to_lowercase(p1);

    EXPECT_EQ(p1, p2);
    EXPECT_EQ(1, bstr_cmp_c(p1, "aRf3ArF"));
    EXPECT_EQ(0, bstr_cmp_c(p1, "arf3arf"));

    bstr_free(p1);
}

TEST(BstrTest, Add) {
    bstr *src1;
    bstr *src2;
    bstr *dest;

    src1 = bstr_dup_c("testtest");
    src2 = bstr_dup_c("0123456789abcdefghijklmnopqrstuvwxyz");
    dest = bstr_add(src1, src2);

    EXPECT_EQ(0, bstr_cmp_c(dest, "testtest0123456789abcdefghijklmnopqrstuvwxyz"));

    // src1 is either invalid or the same as dest after bstr_add
    bstr_free(src2);
    bstr_free(dest);
}

TEST(BstrTest, AddC) {
    bstr *p1;
    bstr *p2;
    p1 = bstr_dup_c("testtest");
    p2 = bstr_add_c(p1, "1234");

    EXPECT_EQ(0, bstr_cmp_c(p2, "testtest1234"));

    bstr_free(p2);
}

TEST(BstrTest, AddMem) {
    bstr *p1;
    bstr *p2;
    p1 = bstr_dup_c("testtest");
    p2 = bstr_add_mem(p1, "12345678", 4);

    EXPECT_EQ(0, bstr_cmp_c(p2, "testtest1234"));

    bstr_free(p2);
}

TEST(BstrTest, AddNoex) {
    bstr *p1;
    bstr *p2;
    bstr *p3;
    p1 = bstr_alloc(10);
    p1 = bstr_add_c(p1, "12345");
    p2 = bstr_dup_c("abcdef");
    p3 = bstr_add_noex(p1,p2);

    EXPECT_EQ(p1,p3);
    EXPECT_EQ(0,bstr_cmp_c(p3,"12345abcde"));
    bstr_free(p1);
    bstr_free(p2);
}

TEST(BstrTest, AddCNoex) {
    bstr *p1;
    bstr *p2;
    p1 = bstr_alloc(10);
    p1 = bstr_add_c(p1, "12345");
    p2 = bstr_add_c_noex(p1,"abcdefghijk");

    EXPECT_EQ(p1,p2);
    EXPECT_EQ(0,bstr_cmp_c(p2,"12345abcde"));

    bstr_free(p1);
}

TEST(BstrTest, AddMemNoex) {
    bstr *p1;
    bstr *p2;
    p1 = bstr_alloc(10);
    p1 = bstr_add_c(p1, "12345");
    p2 = bstr_add_mem_noex(p1,"abcdefghijklmnop",6);

    EXPECT_EQ(p1,p2);
    EXPECT_EQ(0,bstr_cmp_c(p2,"12345abcde"));

    bstr_free(p1);
}

TEST(BstrTest, IndexOf) {
    bstr *haystack = bstr_dup_mem("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20);
    bstr *p1 = bstr_dup_c("NOPQ");
    bstr *p2 = bstr_dup_c("siej");
    bstr *p3 = bstr_dup_c("TUVWXYZ");
    bstr *p4 = bstr_dup_c("nopq");
    EXPECT_EQ(13, bstr_index_of(haystack, p1));
    EXPECT_EQ(-1, bstr_index_of(haystack, p2));
    EXPECT_EQ(-1, bstr_index_of(haystack, p3));

    EXPECT_EQ(-1, bstr_index_of(haystack, p4));
    EXPECT_EQ(13, bstr_index_of_nocase(haystack, p4));

    EXPECT_EQ(16, bstr_index_of_c(haystack, "QRS"));
    EXPECT_EQ(-1, bstr_index_of_c(haystack, "qrs"));
    EXPECT_EQ(16, bstr_index_of_c_nocase(haystack, "qrs"));

    EXPECT_EQ(16, bstr_index_of_mem(haystack, "QRSSDF",3));
    EXPECT_EQ(-1, bstr_index_of_mem(haystack, "qrssdf",3));
    EXPECT_EQ(16, bstr_index_of_mem_nocase(haystack, "qrssdf",3));

    bstr_free(p1);
    bstr_free(p2);
    bstr_free(p3);
    bstr_free(p4);
    bstr_free(haystack);
}

TEST(BstrTest, MemIndexOf) {
    EXPECT_EQ(0, bstr_util_mem_index_of_c("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20, "ABC"));
    EXPECT_EQ(-1, bstr_util_mem_index_of_c("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20, "ABD"));
    EXPECT_EQ(-1, bstr_util_mem_index_of_c("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20, "CBA"));
}

TEST(BstrTest, BeginsWith) {
    bstr *haystack = bstr_dup_mem("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20);
    bstr *p1 = bstr_dup_c("ABCD");
    bstr *p2 = bstr_dup_c("aBcD");

    EXPECT_EQ(1, bstr_begins_with(haystack,p1));
    EXPECT_NE(1, bstr_begins_with(haystack,p2));
    EXPECT_EQ(1, bstr_begins_with_nocase(haystack,p2));

    EXPECT_EQ(1, bstr_begins_with_c(haystack, "AB"));
    EXPECT_NE(1, bstr_begins_with_c(haystack, "ab"));
    EXPECT_EQ(1, bstr_begins_with_c_nocase(haystack, "ab"));

    EXPECT_EQ(1, bstr_begins_with_mem(haystack, "ABq",2));
    EXPECT_NE(1, bstr_begins_with_mem(haystack, "abq",2));
    EXPECT_EQ(1, bstr_begins_with_mem_nocase(haystack, "abq",2));

    bstr_free(p1);
    bstr_free(p2);
    bstr_free(haystack);
}

TEST(BstrTest, BeginsWith2) {
    bstr *haystack = bstr_dup_c("ABC");
    bstr *p1 = bstr_dup_c("ABCD");
    bstr *p2 = bstr_dup_c("EDFG");

    EXPECT_EQ(0, bstr_begins_with_mem(haystack, bstr_ptr(p1), bstr_len(p1)));
    EXPECT_EQ(0, bstr_begins_with_mem_nocase(haystack, bstr_ptr(p1), bstr_len(p1)));
    EXPECT_EQ(0, bstr_begins_with_mem_nocase(haystack, bstr_ptr(p2), bstr_len(p2)));

    bstr_free(p1);
    bstr_free(p2);
    bstr_free(haystack);
}

TEST(BstrTest, CharAt) {
    bstr *str = bstr_dup_mem("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20);
    EXPECT_EQ('\000', bstr_char_at(str, 12));
    EXPECT_EQ(-1, bstr_char_at(str, 45));

    bstr_free(str);
}

TEST(BstrTest, CharAtEnd) {
    bstr *str = bstr_dup_mem("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20);
    EXPECT_EQ('T', bstr_char_at_end(str, 0));
    EXPECT_EQ('\000', bstr_char_at_end(str, 7));
    EXPECT_EQ(-1, bstr_char_at_end(str, bstr_len(str)));

    bstr_free(str);
}

TEST(BstrTest, Chop) {
    bstr *p1 = bstr_dup_c("abcdef");
    bstr *p2 = bstr_alloc(10);
    bstr_chop(p1);
    EXPECT_EQ(0, bstr_cmp_c(p1,"abcde"));

    bstr_chop(p2);
    EXPECT_EQ(0, bstr_len(p2));

    bstr_free(p1);
    bstr_free(p2);
}

TEST(BstrTest, AdjustLen) {
    bstr *p1 = bstr_dup_c("abcdef");

    bstr_adjust_len(p1, 3);
    EXPECT_EQ(3, bstr_len(p1));
    EXPECT_EQ(0, bstr_cmp_c(p1,"abc"));

    bstr_free(p1);
}

TEST(BstrTest, ToPint) {
    size_t lastlen;

    EXPECT_EQ(-1, bstr_util_mem_to_pint("abc", 3, 10, &lastlen));
    EXPECT_EQ(-2, bstr_util_mem_to_pint("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 40, 16, &lastlen));
    EXPECT_EQ(0x7fffffffffffffffLL, bstr_util_mem_to_pint("7fffffffffffffff", 16, 16, &lastlen));
    EXPECT_EQ(-2, bstr_util_mem_to_pint("9223372036854775808", 19, 10, &lastlen));
    EXPECT_EQ(-2, bstr_util_mem_to_pint("555555555555555555555555555555", 30, 10, &lastlen));
    EXPECT_EQ(0xabc, bstr_util_mem_to_pint("abc", 3, 16, &lastlen));
    EXPECT_EQ(4, lastlen);
    EXPECT_EQ(0xabc, bstr_util_mem_to_pint("ABC", 3, 16, &lastlen));
    EXPECT_EQ(131, bstr_util_mem_to_pint("abc", 3, 12, &lastlen));
    EXPECT_EQ(2, lastlen);
    EXPECT_EQ(83474, bstr_util_mem_to_pint("83474abc", 8, 10, &lastlen));
    EXPECT_EQ(5, lastlen);
    EXPECT_EQ(5, bstr_util_mem_to_pint("0101", 4, 2, &lastlen));
    EXPECT_EQ(5, lastlen);
    EXPECT_EQ(5, bstr_util_mem_to_pint("0101", 4, 2, &lastlen));
    EXPECT_EQ(5, lastlen);
}

TEST(BstrTest, DupToC) {
    char *c;
    bstr *str = bstr_dup_mem("ABCDEFGHIJKL\000NOPQRSTUVWXYZ", 20);

    c = bstr_util_memdup_to_c("1234\0006789", 9);
    EXPECT_STREQ("1234\\06789", c);
    free(c);

    c = bstr_util_strdup_to_c(str);
    EXPECT_STREQ("ABCDEFGHIJKL\\0NOPQRST", c);

    free(c);
    bstr_free(str);
}

TEST(BstrTest, RChr) {
    bstr *b = bstr_dup_c("---I---I---");

    EXPECT_EQ(bstr_rchr(b, 'I'), 7);
    EXPECT_EQ(bstr_rchr(b, 'M'), -1);

    bstr_free(b);
}

TEST(BstrTest, AdjustRealPtr) {
    bstr *b = bstr_dup_c("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    char c[] = "0123456789";

    bstr_adjust_realptr(b, c);
    bstr_adjust_len(b, strlen(c));

    EXPECT_TRUE((char *)bstr_ptr(b) == c);

    bstr_free(b);
}

TEST(BstrTest, UtilMemTrim) {
    char d[] = " \r\t0123456789\f\v  ";
    char *data = &d[0];
    size_t len = strlen(data);

    bstr_util_mem_trim((unsigned char **)&data, &len);

    EXPECT_EQ(0, bstr_util_cmp_mem(data, len, "0123456789", 10));
}

TEST(BstrTest, Wrap) {
    bstr *s = bstr_wrap_c("ABC");
    EXPECT_EQ(0, bstr_cmp_mem(s, "ABC", 3));
    bstr_free(s);
}

TEST(BstrBuilder, CreateDestroy) {
    bstr_builder_t *bb = bstr_builder_create();
    EXPECT_EQ(0, bstr_builder_size(bb));

    bstr_builder_append_c(bb, "ABC");

    bstr_builder_destroy(bb);
}

TEST(BstrBuilder, Append) {
    bstr_builder_t *bb = bstr_builder_create();
    bstr *str1 = bstr_dup_c("0123456789");
    bstr *str2 = bstr_dup_c("abcdefghijklmnopqrstuvwxyz");

    EXPECT_EQ(0, bstr_builder_size(bb));

    bstr_builder_appendn(bb, str1);
    bstr_builder_append_c(bb, "#");
    bstr_builder_appendn(bb, str2);
    bstr_builder_append_c(bb, "#");
    bstr_builder_append_mem(bb, "!@#$%^&*()", 4);

    EXPECT_EQ(5, bstr_builder_size(bb));

    bstr *result = bstr_builder_to_str(bb);
    EXPECT_EQ(42, bstr_len(result));

    EXPECT_EQ(0, memcmp("0123456789#abcdefghijklmnopqrstuvwxyz#!@#$",
                        bstr_ptr(result),42));
    bstr_free(result);

    bstr_builder_clear(bb);
    EXPECT_EQ(0, bstr_builder_size(bb));

    bstr_builder_destroy(bb);
}
