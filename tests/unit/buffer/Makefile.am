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

UUT = $(openvpn_srcdir)/buffer.c

# If any test is expected to fail (eg, new test, WIP, on TODO list), add it here
XFAIL_TESTS =

# Force base64 to be built and tested even if the build configuration don't
# use it. If it's implemented, it gets tested.
activation_CPPFLAGS =

# Mutators are pre-processor defines that alter the source code
# They will be removed from the local config.h if defined
mutators = ENABLE_DEBUG \
    ZERO_BUFFER_ON_ALLOC \
    DMALLOC \
    CHARACTER_CLASS_DEBUG \
    ENABLE_BUFFER_LIST \
    BUF_INIT_TRACKING \
    VERIFY_ALIGNMENT

if IMPLEMENTED_buffer_2_0
activation_CPPFLAGS += -DIMPLEMENTATION_2_0
endif

if IMPLEMENTED_buffer_2_2
activation_CPPFLAGS += -DIMPLEMENTATION_2_2
endif

if IMPLEMENTED_buffer_2_3
activation_CPPFLAGS += -DIMPLEMENTATION_2_3
endif

if IMPLEMENTED_buffer_2_4
activation_CPPFLAGS += -DIMPLEMENTATION_2_4
endif

if IMPLEMENTED_buffer_2_5
activation_CPPFLAGS += -DIMPLEMENTATION_2_5
endif

# TEST_SUITE_LOG=blah.log

# tests to be run by developers/maintainers, --enable-unit-tests=all
# This selection implements stringent memory checks with both cmocka dynamic
# memory verification, and valgrind memcheck. It also tests some variety of
# build configurations, with various features enabled or disabled, as is
# appropriate for the Unit-under-test.
# Specifically in the case of buffer, there are a number of ASSERTIONS used
# so -DNDEBUG will be tested, and the following behaviour changing defines:
#
all_tests =	memleaks.memcheck \
		ndebug.test \
		base.buffer.kitchen-sink.test

# Tests run by package maintainers, only validate the active configuration
# This test selection validates functionality, basic memory leak, and basic
# buffer overrun/underrun checks. These are only intended to check that
# a bug was not triggered by the builder's environment.
sanity_tests =  sanity.buffer.test

base_test_CFLAGS        = @CMOCKA_CFLAGS@ -Wall -Werror @TEST_CFLAGS@
base_test_LDADD         = @CMOCKA_LIBS@ @MATH_LIBS@
base_test_SOURCES       = config.h test.c $(UUT)
base_test_CPPFLAGS      = @TEST_CPPFLAGS@ \
				-include $(testlib_srcdir)/moerror.h \
				$(activation_CPPFLAGS) \
				-I$(openvpn_srcdir) \
				-I$(compat_srcdir)

sanity_buffer_test_CFLAGS    = $(base_test_CFLAGS)
sanity_buffer_test_LDADD     = $(base_test_LDADD)
sanity_buffer_test_SOURCES   = $(base_test_SOURCES)
sanity_buffer_test_CPPFLAGS  = -I$(top_builddir) $(base_test_CPPFLAGS)

if IMPLEMENTED_rfc4821

all_tests += memleaks.buffer-rfc4821.memcheck \
	    ndebug.buffer-rfc4821.test

memleaks_buffer_rfc4821_memcheck_CFLAGS    = $(base_test_CFLAGS) $(memcheck_cflags)
memleaks_buffer_rfc4821_memcheck_LDADD     = $(base_test_LDADD)
memleaks_buffer_rfc4821_memcheck_SOURCES   = config.h test-rfc4821.c $(UUT)
memleaks_buffer_rfc4821_memcheck_CPPFLAGS  = -I. $(base_test_CPPFLAGS) $(memcheck_cppflags)  -DUNIT_TESTS_ALL

ndebug_buffer_rfc4821_test_CFLAGS    = $(base_test_CFLAGS)
ndebug_buffer_rfc4821_test_LDADD     = $(base_test_LDADD)
ndebug_buffer_rfc4821_test_SOURCES   = config.h test-rfc4821.c $(UUT)
ndebug_buffer_rfc4821_test_CPPFLAGS  = -DNDEBUG \
				    -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

endif

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
memleaks_memcheck_CPPFLAGS  = -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

# Enable all the known build switches. This is not a targetted test, just looks
# for easy to catch compile errors.
# The kitchen-sink test fails due to an apparent bug in dmalloc triggered by
# cmocka (https://github.com/drok/ovpn/issues/7)
XFAIL_TESTS += base.buffer.kitchen-sink.test

# Ideally, some tests in test.c target these modes to make sure they do what
# is intended.
# Does this combination of switches build and produce a sane binary?
base_buffer_kitchen_sink_test_CFLAGS    = $(base_test_CFLAGS)
base_buffer_kitchen_sink_test_LDADD     = $(base_test_LDADD) @DMALLOC_LIBS@
base_buffer_kitchen_sink_test_SOURCES   = $(base_test_SOURCES)
base_buffer_kitchen_sink_test_CPPFLAGS  = \
				   -DZERO_BUFFER_ON_ALLOC \
				   -DCHARACTER_CLASS_DEBUG \
				   -DVERIFY_ALIGNMENT \
				   -DENABLE_BUFFER_LIST \
				   -DDMALLOC \
			     -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL
endif

TESTS = $(check_PROGRAMS)
