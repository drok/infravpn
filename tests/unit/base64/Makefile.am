#  Tests   -- A test infrastructure for backwards-compatible testing
#
#  Copyright (C) 2020 Radu Hociung <radu.tests@ohmi.org>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
AUTOMAKE_OPTIONS = color-tests parallel-tests

include $(top_srcdir)/tests/srcpaths.inc

UUT = $(openvpn_srcdir)/base64.c

# If any test is expected to fail (eg, new test, WIP, on TODO list), add it here
XFAIL_TESTS =

# Force base64 to be built and tested even if the build configuration don't
# use it. If it's implemented, it gets tested.
activation_CPPFLAGS = -DSYSHEAD_H -DNTLM

# TEST_SUITE_LOG=blah.log

# tests to be run by developers/maintainers, --enable-unit-tests=all
# This selection implements stringent memory checks with both cmocka dynamic
# memory verification, and valgrind memcheck. It also tests some variety of
# build configurations, with various features enabled or disabled, as is
# appropriate for the Unit-under-test.
# Specifically in the case of base64, there are no conditional compilation
# options, but the -DNDEBUG and -DENABLE_DEBUG options are tested,
# as an illustration as this is a template unit test.
all_tests =	memleaks.memcheck \
		ndebug.test \
		debug.test

# Tests run by package maintainers, only validate the active configuration
# This test selection validates functionality, basic memory leak, and basic
# buffer overrun/underrun checks. These are only intended to check that
# a bug was not triggered by the builder's environment.
sanity_tests =  sanity.base64.test

base_test_CFLAGS        = @CMOCKA_CFLAGS@ -Wall -Werror @TEST_CFLAGS@
base_test_LDADD         = @CMOCKA_LIBS@
base_test_SOURCES       = config.h test.c $(UUT)
base_test_CPPFLAGS      = @TEST_CPPFLAGS@ \
				-include $(testlib_srcdir)/moerror.h \
				$(activation_CPPFLAGS) \
				-I$(openvpn_srcdir) \
				-I$(compat_srcdir)

sanity_base64_test_CFLAGS    = $(base_test_CFLAGS)
sanity_base64_test_LDADD     = $(base_test_LDADD)
sanity_base64_test_SOURCES   = $(base_test_SOURCES)
sanity_base64_test_CPPFLAGS  = $(base_test_CPPFLAGS)

# -- Anything below this line can be reused as-is in most other tests ----------

if !ENABLE_UNITTESTS_ALL
check_PROGRAMS = $(sanity_tests)
else
check_PROGRAMS = $(sanity_tests) $(all_tests)

# Override $top_build_dir/config.h with local version so some defines can be
# specified as CPPFLAGS
BUILT_SOURCES = config.h
CLEANFILES = config.h
config.h : $(top_builddir)/config.h
	$(SED) -r '/#define ENABLE_(DEBUG)/d' $< >$@


# While base64 uses neither ASSERT() nor ENABLE_DEBUG, this example demonstrates
# thorough testing, and the ability to find simple but impactful bugs very
# cheaply, with no additional code written. In fact, the makefile content below
# this line can likely be used as is in new tests, without anything touched.
# IMPORTANT: This test suite can run on any version of the project, ancient or
# future. Don't cripple the test by removing test configs that don't appear to
# be useful in the branch you are working on. Alternately, make sure your
# optimizations only affect your branch of interest (eg, don't cherry-pick them
# into the tests repo)

# The ndebug build is very similar to the plain build in many versions of the
# project. But there are (or will be) some versions where the ASSERT macro calls
# the standard glibc assert() instead of the openvpn assert_failed() function.
# These versions will be broken if built with -DNDEBUG and where the the
# ASSERT() expression modifies program state. To remove the ndebug test
# in the test branch would leave other source branches vulnerable/blind
# to bugs like ASSERT() that modify state.
# TDLR: Do not remove the _ndebug_ tests.
ndebug_test_CFLAGS    = $(base_test_CFLAGS)
ndebug_test_LDADD     = $(base_test_LDADD)
ndebug_test_SOURCES   = $(base_test_SOURCES)
ndebug_test_CPPFLAGS  = -DNDEBUG \
			 $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

# Enabled debugging is not supposed to modify behaviour, but sometimes
# active code is forgotten surrounded by #test ENABLE_DEBUG
# this test may help catch those.
debug_test_CFLAGS	= $(base_test_CFLAGS)
debug_test_LDADD	= $(base_test_LDADD)
debug_test_SOURCES     = $(base_test_SOURCES)
debug_test_CPPFLAGS    = -DENABLE_DEBUG \
			  $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

memleaks_memcheck_CFLAGS    = $(base_test_CFLAGS) $(memcheck_cflags)
memleaks_memcheck_LDADD     = $(base_test_LDADD)
memleaks_memcheck_SOURCES   = $(base_test_SOURCES)
memleaks_memcheck_CPPFLAGS  = $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL
endif

TESTS = $(check_PROGRAMS)
