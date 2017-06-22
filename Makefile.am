
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = htp test docs

DIST_SUBDIRS = htp test docs
EXTRA_DIST = LICENSE NOTICE docs/doxygen.conf docs/QUICK_START VERSION get-version.sh \
		docs/COMPATIBILITY_CHANGES

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = htp.pc

test: all
	@(cd test && $(MAKE) $@)

test-compile-only: all
	@(cd test && $(MAKE) $@)

check-compile-only: all
	@(cd test && $(MAKE) $@)

doxygen doxygen-pdf:
	@(cd docs && $(MAKE) $@)

gcov: test		
	@ if [[ -x $(LCOV) ]]; then \
		lcov --capture --directory $(top_builddir)/htp/ --output-file $(top_builddir)/test/coverage.info --no-external ; \
		genhtml $(top_builddir)/test/coverage.info --output-directory $(top_builddir)/docs/lcov ; \
		echo "" ; \
		echo "Open docs/lcov/index.html to review lcov output" ; \
	fi

clean-local:
	rm -rf $(top_builddir)/docs/doxygen
	rm -rf $(top_builddir)/docs/lcov
	find $(top_builddir) -type f \( -name '*.gcda' -o -name '*.gcno' -o -name '*.gcov' \) -exec rm '{}' ';'

