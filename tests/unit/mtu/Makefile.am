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

UUT = $(openvpn_srcdir)/mtu.c

# If any test is expected to fail (eg, new test, WIP, on TODO list), add it here
XFAIL_TESTS =

# Force base64 to be built and tested even if the build configuration don't
# use it. If it's implemented, it gets tested.
activation_CPPFLAGS =
# -DSYSHEAD_H

# Mutators are pre-processor defines that alter the source code
# They will be removed from the local config.h if defined
mutators = ENABLE_DEBUG \
    LINK_MSS \
    ENABLE_SSL \
    ENABLE_CRYPTO \
    ENABLE_PLUGIN \
    ENABLE_LZO \
    ENABLE_FRAGMENT

if IMPLEMENTED_mtu_2_0
activation_CPPFLAGS += -DIMPLEMENTATION_2_0
endif

if IMPLEMENTED_mtu_2_4
activation_CPPFLAGS += -DIMPLEMENTATION_2_4
endif

if IMPLEMENTED_mtu2
activation_CPPFLAGS += -DIMPLEMENTATION_mtu2
endif

# TEST_SUITE_LOG=blah.log

# tests to be run by developers/maintainers, --enable-unit-tests=all
# This selection implements stringent memory checks with both cmocka dynamic
# memory verification, and valgrind memcheck. It also tests some variety of
# build configurations, with various features enabled or disabled, as is
# appropriate for the Unit-under-test.
# Specifically in the case of mtu, it depends on:
# NDEBUG    - many ASSERT()
# ENABLE_LZO    - interfaces and arithmetic are different with LZO compression
# ENABLE_FRAGMENT - interfaces and arithmetic are diff with FRAGMENT support.

all_tests = ndebug.test \
                debug.test \
        algo.mtu-lzo.test \
        algo.mtu-lzo-crypto.test \
        algo.mtu-lzo-ssl-crypto.test \
        algo.mtu-fragment.test \
        algo.mtu-lzo-fragment.test \
        algo.mtu-lzo-fragment-mss.test \
        algo.mtu-lzo-fragment-mss-ssl-crypto.test \
        ndebug.mtu-lzo-fragment.test

# Tests run by package maintainers, only validate the active configuration
# This test selection validates functionality, basic memory leak, and basic
# buffer overrun/underrun checks. These are only intended to check that
# a bug was not triggered by the builder's environment.
sanity_tests =  sanity.mtu.test

base_test_CFLAGS        = @CMOCKA_CFLAGS@ -Wall -Werror @TEST_CFLAGS@
base_test_LDADD         = @CMOCKA_LIBS@
base_test_SOURCES       = config.h test.c $(UUT)
base_test_CPPFLAGS      = @TEST_CPPFLAGS@ \
                -include $(testlib_srcdir)/moerror.h \
                $(activation_CPPFLAGS) \
                -I$(openvpn_srcdir) \
                -I$(compat_srcdir)

sanity_mtu_test_CFLAGS    = $(base_test_CFLAGS)
sanity_mtu_test_LDADD     = $(base_test_LDADD)
sanity_mtu_test_SOURCES   = $(base_test_SOURCES)
sanity_mtu_test_CPPFLAGS  = -I$(top_builddir) $(base_test_CPPFLAGS) \
			    -I$(openvpn_includedir)

# -- Anything below this line can be reused as-is in most other tests ----------

if !ENABLE_UNITTESTS_ALL
check_PROGRAMS = $(sanity_tests)
else
check_PROGRAMS = $(sanity_tests) $(all_tests)

ndebug_test_CFLAGS    = $(base_test_CFLAGS)
ndebug_test_LDADD     = $(base_test_LDADD)
ndebug_test_SOURCES   = $(base_test_SOURCES)
ndebug_test_CPPFLAGS  = -DNDEBUG \
             -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

debug_test_CFLAGS   = $(base_test_CFLAGS)
debug_test_LDADD    = $(base_test_LDADD)
debug_test_SOURCES      = $(base_test_SOURCES)
debug_test_CPPFLAGS     = -DENABLE_DEBUG \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

algo_mtu_lzo_test_CFLAGS   = $(base_test_CFLAGS)
algo_mtu_lzo_test_LDADD    = $(base_test_LDADD)
algo_mtu_lzo_test_SOURCES  = $(base_test_SOURCES)
algo_mtu_lzo_test_CPPFLAGS = -DENABLE_LZO \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

algo_mtu_lzo_crypto_test_CFLAGS   = $(base_test_CFLAGS)
algo_mtu_lzo_crypto_test_LDADD    = $(base_test_LDADD)
algo_mtu_lzo_crypto_test_SOURCES  = $(base_test_SOURCES)
algo_mtu_lzo_crypto_test_CPPFLAGS = -DENABLE_LZO -DENABLE_CRYPTO -DENABLE_CRYPTO_OPENSSL \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

algo_mtu_lzo_ssl_crypto_test_CFLAGS   = $(base_test_CFLAGS)
algo_mtu_lzo_ssl_crypto_test_LDADD    = $(base_test_LDADD)
algo_mtu_lzo_ssl_crypto_test_SOURCES  = $(base_test_SOURCES)
algo_mtu_lzo_ssl_crypto_test_CPPFLAGS = -DENABLE_LZO -DENABLE_SSL -DENABLE_CRYPTO -DENABLE_CRYPTO_OPENSSL \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

algo_mtu_fragment_test_CFLAGS   = $(base_test_CFLAGS)
algo_mtu_fragment_test_LDADD    = $(base_test_LDADD)
algo_mtu_fragment_test_SOURCES  = $(base_test_SOURCES)
algo_mtu_fragment_test_CPPFLAGS = -DENABLE_FRAGMENT \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

algo_mtu_lzo_fragment_test_CFLAGS   = $(base_test_CFLAGS)
algo_mtu_lzo_fragment_test_LDADD    = $(base_test_LDADD)
algo_mtu_lzo_fragment_test_SOURCES  = $(base_test_SOURCES)
algo_mtu_lzo_fragment_test_CPPFLAGS = -DENABLE_LZO -DENABLE_FRAGMENT \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

algo_mtu_lzo_fragment_mss_test_CFLAGS   = $(base_test_CFLAGS)
algo_mtu_lzo_fragment_mss_test_LDADD    = $(base_test_LDADD)
algo_mtu_lzo_fragment_mss_test_SOURCES  = $(base_test_SOURCES)
algo_mtu_lzo_fragment_mss_test_CPPFLAGS = -DENABLE_LZO -DENABLE_FRAGMENT -DLINK_MSS=8972 \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

algo_mtu_lzo_fragment_mss_ssl_crypto_test_CFLAGS   = $(base_test_CFLAGS)
algo_mtu_lzo_fragment_mss_ssl_crypto_test_LDADD    = $(base_test_LDADD)
algo_mtu_lzo_fragment_mss_ssl_crypto_test_SOURCES  = $(base_test_SOURCES)
algo_mtu_lzo_fragment_mss_ssl_crypto_test_CPPFLAGS = -DENABLE_LZO -DENABLE_FRAGMENT \
                                                     -DLINK_MSS=8972 \
                                                     -DENABLE_SSL -DENABLE_CRYPTO -DENABLE_CRYPTO_OPENSSL \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

ndebug_mtu_lzo_fragment_test_CFLAGS   = $(base_test_CFLAGS)
ndebug_mtu_lzo_fragment_test_LDADD    = $(base_test_LDADD)
ndebug_mtu_lzo_fragment_test_SOURCES  = $(base_test_SOURCES)
ndebug_mtu_lzo_fragment_test_CPPFLAGS = -DNDEBUG -DENABLE_LZO -DENABLE_FRAGMENT \
              -I. $(base_test_CPPFLAGS) -DUNIT_TESTS_ALL

endif

TESTS = $(check_PROGRAMS)
