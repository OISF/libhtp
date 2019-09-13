
h_sources = LzmaDec.h 7zTypes.h

h_sources_private = LzFind.h LzHash.h Compiler.h Precomp.h

c_sources = LzFind.c LzmaDec.c

AM_CFLAGS = -I$(top_srcdir) -D_GNU_SOURCE -g -Wall -Wextra -std=gnu99 -pedantic \
    -Wextra -Wno-missing-field-initializers -Wshadow -Wpointer-arith \
    -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter

library_includedir = $(includedir)/$(GENERIC_LIBRARY_NAME)/lzma
library_include_HEADERS = $(h_sources)

noinst_LTLIBRARIES = liblzma-c.la
liblzma_c_la_SOURCES = $(h_sources) $(h_sources_private) $(c_sources)
