
h_sources = LzmaDec.h

h_sources_private = 7zTypes.h LzFind.h LzHash.h Compiler.h Precomp.h

c_sources = LzFind.c LzmaDec.c

AM_CFLAGS = -I$(top_srcdir) -D_GNU_SOURCE -g -Wall -Wextra -std=c11 -pedantic \
    -Wextra -Wno-missing-field-initializers -Wshadow -Wpointer-arith \
    -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter

noinst_LTLIBRARIES = liblzma-c.la
liblzma_c_la_SOURCES = $(h_sources) $(h_sources_private) $(c_sources)
