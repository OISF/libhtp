LDADD = $(top_builddir)/htp/libhtp.la -lz @LIBICONV@ 

AM_CFLAGS = -D_GNU_SOURCE -g -Wall -Wextra -std=gnu99 -pedantic \
	-Wextra -Wno-missing-field-initializers -Wshadow -Wpointer-arith \
        -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter
        
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir)/htp -Wno-write-strings -DGTEST_USE_OWN_TR1_TUPLE=1 \
	-D_GNU_SOURCE -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare

AUTOMAKE_OPTIONS = subdir-objects
EXTRA_DIST = files
check_PROGRAMS = test_all test_fuzz
check_LIBRARIES = libgtest.a

test_all_SOURCES = test_bstr.cpp test_gunzip.cpp test_hybrid.cpp test_main.cpp test_multipart.cpp test.c test.h test_utils.cpp test_bench.cpp
test_all_LDADD = libgtest.a -lpthread $(LDADD)

test_fuzz_SOURCES = fuzz/onefile.c fuzz/fuzz_htp.c fuzz/fuzz_htp.h test.c
test_fuzz_LDADD = $(LDADD)

libgtest_a_SOURCES = gtest/gtest-all.cc gtest/gtest_main.cc gtest/gtest.h

TESTS_ENVIRONMENT = srcdir=$(srcdir)/files
TESTS = test_all

test: check
	@echo

test-compile-only: all-am
	$(MAKE) $(AM_MAKEFLAGS) $(check_LIBRARIES)
	$(MAKE) $(AM_MAKEFLAGS) $(check_PROGRAMS)

check-compile-only: all-am
	$(MAKE) $(AM_MAKEFLAGS) $(check_LIBRARIES)
	$(MAKE) $(AM_MAKEFLAGS) $(check_PROGRAMS)

