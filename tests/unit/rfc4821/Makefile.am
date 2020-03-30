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
AUTOMAKE_OPTIONS = color-tests parallel-tests nostdinc

include $(top_srcdir)/tests/srcpaths.inc
include $(top_srcdir)/tests/unit/rules.inc

UUT = $(openvpn_srcdir)/rfc4821.c

# If any test is expected to fail (eg, new test, WIP, on TODO list), add it here
XFAIL_TESTS =

# Force base64 to be built and tested even if the build configuration don't
# use it. If it's implemented, it gets tested.
activation_CPPFLAGS =
# -DSYSHEAD_H

# Mutators are pre-processor defines that alter the source code
# They will be removed from the local config.h if defined
mutators = ENABLE_DEBUG

if IMPLEMENTED_rfc4821
# Nothing to do. The implementation is at its initial revision
endif

# TEST_SUITE_LOG=blah.log

# tests to be run by developers/maintainers, --enable-unit-tests=all
# This selection implements stringent memory checks with both cmocka dynamic
# memory verification, and valgrind memcheck. It also tests some variety of
# build configurations, with various features enabled or disabled, as is
# appropriate for the Unit-under-test.
# Specifically in the case of rfc4821, there are a number of ASSERTIONS used
# so -DNDEBUG will be tested.
all_tests =	memleaks.memcheck \
		ndebug.test

# Tests run by package maintainers, only validate the active configuration
# This test selection validates functionality, basic memory leak, and basic
# buffer overrun/underrun checks. These are only intended to check that
# a bug was not triggered by the builder's environment.
sanity_tests =  sanity.rfc4821.test

base_test_CFLAGS        = @CMOCKA_CFLAGS@ -Wall -Werror @TEST_CFLAGS@
base_test_LDADD         = @CMOCKA_LIBS@ @MATH_LIBS@
base_test_SOURCES       = config.h test.c $(UUT)
base_test_CPPFLAGS      = @TEST_CPPFLAGS@ \
				-include $(testlib_srcdir)/moerror.h \
				$(activation_CPPFLAGS) \
				-I$(openvpn_srcdir) \
				-I$(compat_srcdir)

sanity_rfc4821_test_CFLAGS    = $(base_test_CFLAGS)
sanity_rfc4821_test_LDADD     = $(base_test_LDADD)
sanity_rfc4821_test_SOURCES   = $(base_test_SOURCES)
sanity_rfc4821_test_CPPFLAGS  = -I$(top_builddir) $(base_test_CPPFLAGS)

# -- Anything below this line can be reused as-is in most other tests ----------

if !ENABLE_UNITTESTS_ALL
check_PROGRAMS = $(sanity_tests)
else
check_PROGRAMS = $(sanity_tests) $(all_tests)

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
			 -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

memleaks_memcheck_CFLAGS    = $(base_test_CFLAGS) $(memcheck_cflags)
memleaks_memcheck_LDADD     = $(base_test_LDADD)
memleaks_memcheck_SOURCES   = $(base_test_SOURCES)
memleaks_memcheck_CPPFLAGS  = -I. $(base_test_CPPFLAGS) $(memcheck_cppflags) -DUNIT_TESTS_ALL
endif

TESTS = $(check_PROGRAMS)
