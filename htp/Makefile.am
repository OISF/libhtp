
h_sources = bstr.h bstr_builder.h htp.h htp_base64.h htp_config.h htp_connection_parser.h \
    htp_core.h htp_decompressors.h htp_hooks.h htp_list.h \
    htp_multipart.h htp_table.h htp_transaction.h \
    htp_urlencoded.h htp_utf8_decoder.h htp_version.h

h_sources_private = htp_config_private.h htp_connection_private.h htp_connection_parser_private.h htp_list_private.h \
    htp_multipart_private.h htp_private.h htp_table_private.h htp_config_auto.h

c_sources = bstr.c bstr_builder.c htp_base64.c htp_config.c htp_connection.c htp_connection_parser.c \
    htp_content_handlers.c htp_cookies.c htp_decompressors.c htp_hooks.c  htp_list.c htp_multipart.c htp_parsers.c \
    htp_php.c htp_request.c htp_request_apache_2_2.c htp_request_generic.c htp_request_parsers.c htp_response.c \
    htp_response_generic.c htp_table.c htp_transaction.c htp_transcoder.c htp_urlencoded.c htp_util.c htp_utf8_decoder.c \
    strlcpy.c strlcat.c

library_includedir = $(includedir)/$(GENERIC_LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

AM_CFLAGS = -I$(top_srcdir) -I$(top_builddir)/htp -D_GNU_SOURCE -g -Wall -Wextra -std=gnu99 -pedantic \
    -Wextra -Wno-missing-field-initializers -Wshadow -Wpointer-arith \
    -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter

noinst_LTLIBRARIES = libhtp-c.la
libhtp_c_la_SOURCES = $(h_sources) $(h_sources_private) $(c_sources)

lib_LTLIBRARIES = libhtp.la
libhtp_la_SOURCES =
libhtp_la_LIBADD = libhtp-c.la
libhtp_la_LDFLAGS = -version-info $(GENERIC_LIBRARY_VERSION)
