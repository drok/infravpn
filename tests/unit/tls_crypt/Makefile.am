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

UUT = 	$(openvpn_srcdir)/tls_crypt.c

# Additional implementations. Should these be mocked instead of linked?
UUT += \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/crypto.c \
	$(openvpn_srcdir)/crypto_mbedtls.c \
	$(openvpn_srcdir)/crypto_openssl.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/platform.c

# If any test is expected to fail (eg, new test, WIP, on TODO list), add it here
XFAIL_TESTS =

# Are any macros needed to force building the UUT (ENABLE_SSL, etc?)?
activation_CPPFLAGS =

# Mutators are pre-processor defines that alter the source code
# They will be removed from the local config.h if defined
mutators = ENABLE_DEBUG \
    ENABLE_CRYPTO

if IMPLEMENTED_tls_crypt_2_4
activation_CPPFLAGS += -DIMPLEMENTATION_2_4
endif

if IMPLEMENTED_tls_crypt_2_5
activation_CPPFLAGS += -DIMPLEMENTATION_2_5
endif

# TEST_SUITE_LOG=blah.log

# tests to be run by developers/maintainers, --enable-unit-tests=all
# This selection implements stringent memory checks with both cmocka dynamic
# memory verification, and valgrind memcheck. It also tests some variety of
# build configurations, with various features enabled or disabled, as is
# appropriate for the Unit-under-test.
# Specifically for tls_crypt, operation with OPENSSL and MBEDTLS is tested,
# as well as -DNDEBUG and -DENABLE_DEBUGGING
all_tests = protocol.tls_crypt.openssl.test \
                 protocol.tls_crypt.mbedtls.test \
		protocol.nomemchecks.tls_crypt.openssl.test \
		protocol.nomemchecks.tls_crypt.mbedtls.test \
		ndebug.openssl.test \
		ndebug.mbedtls.test \
		memleaks.openssl.memcheck \
		memleaks.mbedtls.memcheck \
		debug.openssl.test \
		debug.mbedtls.test

# Tests run by package maintainers, only validate the active configuration
# This test selection validates functionality, basic memory leak, and basic
# buffer overrun/underrun checks. These are only intended to check that
# a bug was not triggered by the builder's environment.
sanity_tests = sanity.tls_crypt.test

base_ldflags = -Wl,--wrap=buffer_read_from_file \
		-Wl,--wrap=buffer_write_file \
		-Wl,--wrap=parse_line \
		-Wl,--wrap=rand_bytes
base_cppflags = @TEST_CPPFLAGS@ \
		-include $(testlib_srcdir)/moerror.h \
		$(activation_CPPFLAGS) \
		-I$(openvpn_srcdir) \
		-I$(compat_srcdir)


sanity_tls_crypt_test_CFLAGS        = @CMOCKA_CFLAGS@ $(OPTIONAL_CRYPTO_CFLAGS) -Wall -Werror @TEST_CFLAGS@
sanity_tls_crypt_test_LDADD         = @CMOCKA_LIBS@ $(OPTIONAL_CRYPTO_LIBS)
sanity_tls_crypt_test_LDFLAGS       =	$(base_ldflags)
sanity_tls_crypt_test_SOURCES       = config.h test.c $(UUT)
sanity_tls_crypt_test_CPPFLAGS      = -I$(top_builddir) $(base_cppflags)

if !ENABLE_UNITTESTS_ALL
check_PROGRAMS = $(sanity_tests)
else
check_PROGRAMS = $(sanity_tests) $(all_tests)

openssl_cflags = @CMOCKA_CFLAGS@ @OPENSSL_CFLAGS@ -Wall -Werror @TEST_CFLAGS@
openssl_libs = @CMOCKA_LIBS@ @OPENSSL_LIBS@
openssl_cppflags = -I. $(base_cppflags) -DUNIT_TESTS_ALL \
		-DENABLE_CRYPTO -DENABLE_CRYPTO_OPENSSL

mbedtls_cflags = @CMOCKA_CFLAGS@ @MBEDTLS_CFLAGS@ -Wall -Werror @TEST_CFLAGS@
mbedtls_libs = @CMOCKA_LIBS@ @MBEDTLS_LIBS@
mbedtls_cppflags = -I. $(base_cppflags) -DUNIT_TESTS_ALL \
		-DENABLE_CRYPTO -DENABLE_CRYPTO_MBEDTLS

protocol_tls_crypt_openssl_test_CFLAGS        = $(openssl_cflags)
protocol_tls_crypt_openssl_test_LDADD         = $(openssl_libs)
protocol_tls_crypt_openssl_test_LDFLAGS       =	$(base_ldflags)
protocol_tls_crypt_openssl_test_SOURCES       = config.h test.c $(UUT)
protocol_tls_crypt_openssl_test_CPPFLAGS      = $(openssl_cppflags)

protocol_tls_crypt_mbedtls_test_CFLAGS        = $(mbedtls_cflags)
protocol_tls_crypt_mbedtls_test_LDADD         = $(mbedtls_libs)
protocol_tls_crypt_mbedtls_test_LDFLAGS       =	$(base_ldflags)
protocol_tls_crypt_mbedtls_test_SOURCES       = config.h test.c $(UUT)
protocol_tls_crypt_mbedtls_test_CPPFLAGS      = $(mbedtls_cppflags)

# This may be removed. I am including a test withe mocka memory allocation
# checking disabled because it's the only way to get the test to pass, and
# I want to demonstrate that the tests/unit framework is finding bugs, rather
# than causeing bugs.
protocol_nomemchecks_tls_crypt_openssl_test_CFLAGS        = $(openssl_cflags)
protocol_nomemchecks_tls_crypt_openssl_test_LDADD         = $(openssl_libs)
protocol_nomemchecks_tls_crypt_openssl_test_LDFLAGS       = $(base_ldflags)
protocol_nomemchecks_tls_crypt_openssl_test_SOURCES       = config.h test.c $(UUT)
protocol_nomemchecks_tls_crypt_openssl_test_CPPFLAGS      = $(openssl_cppflags) -DNO_CMOCKA_MEMCHECK

protocol_nomemchecks_tls_crypt_mbedtls_test_CFLAGS        = $(mbedtls_cflags)
protocol_nomemchecks_tls_crypt_mbedtls_test_LDADD         = $(mbedtls_libs)
protocol_nomemchecks_tls_crypt_mbedtls_test_LDFLAGS       = $(base_ldflags)
protocol_nomemchecks_tls_crypt_mbedtls_test_SOURCES       = config.h test.c $(UUT)
protocol_nomemchecks_tls_crypt_mbedtls_test_CPPFLAGS      = $(mbedtls_cppflags) -DNO_CMOCKA_MEMCHECK

# -- Anything below this line can be reused as-is in most other tests ----------

# The ndebug build is very similar to the plain build in many versions of the
# project. But there are (or will be) some branches where the ASSERT macro calls
# the standard glibc assert() instead of the openvpn assert_failed() function.
# These versions will be broken if built with -DNDEBUG and where the the
# ASSERT() expression has side effects. To remove the ndebug test
# in the test branch would leave other source branches vulnerable/blind
# to bugs like ASSERT() with side effects.
#
# Eg. At the time this test was ported from tests/unit_tests to tests/unit,
# this bug exists in tls_crypt.c:138 in the openvpn release/2.4 branch:
#
# ASSERT(tag = buf_write_alloc(dst, TLS_CRYPT_TAG_SIZE));
#
# The programmer cannot make that guarantee. Asserts should be reserved for
# programmer's guarantees.
#
# TDLR: Do not remove the _ndebug_ tests.
ndebug_openssl_test_CFLAGS    = $(openssl_cflags)
ndebug_openssl_test_LDADD     = $(openssl_libs)
ndebug_openssl_test_LDFLAGS   = $(base_ldflags)
ndebug_openssl_test_SOURCES   = config.h test.c $(UUT)
ndebug_openssl_test_CPPFLAGS  = -DNDEBUG $(openssl_cppflags)

ndebug_mbedtls_test_CFLAGS    = $(mbedtls_cflags)
ndebug_mbedtls_test_LDADD     = $(mbedtls_libs)
ndebug_mbedtls_test_LDFLAGS   = $(base_ldflags)
ndebug_mbedtls_test_SOURCES   = config.h test.c $(UUT)
ndebug_mbedtls_test_CPPFLAGS  = -DNDEBUG $(mbedtls_cppflags)

# Enabled debugging is not supposed to modify behaviour, but sometimes
# active code is forgotten surrounded by #test ENABLE_DEBUG
# this test may help catch those.
debug_openssl_test_CFLAGS    = $(openssl_cflags)
debug_openssl_test_LDADD     = $(openssl_libs)
debug_openssl_test_LDFLAGS   = $(base_ldflags)
debug_openssl_test_SOURCES   = config.h test.c $(UUT)
debug_openssl_test_CPPFLAGS  = -DENABLE_DEBUG $(openssl_cppflags)

debug_mbedtls_test_CFLAGS    = $(mbedtls_cflags)
debug_mbedtls_test_LDADD     = $(mbedtls_libs)
debug_mbedtls_test_LDFLAGS   = $(base_ldflags)
debug_mbedtls_test_SOURCES   = config.h test.c $(UUT)
debug_mbedtls_test_CPPFLAGS  = -DENABLE_DEBUG $(mbedtls_cppflags)

memleaks_openssl_memcheck_CFLAGS    = $(openssl_cflags) $(memcheck_cflags)
memleaks_openssl_memcheck_LDADD     = $(openssl_libs)
memleaks_openssl_memcheck_LDFLAGS   = $(base_ldflags)
memleaks_openssl_memcheck_SOURCES   = config.h test.c $(UUT)
memleaks_openssl_memcheck_CPPFLAGS  = -DENABLE_DEBUG $(openssl_cppflags) $(memcheck_cppflags)

memleaks_mbedtls_memcheck_CFLAGS    = $(mbedtls_cflags) $(memcheck_cflags)
memleaks_mbedtls_memcheck_LDADD     = $(mbedtls_libs)
memleaks_mbedtls_memcheck_LDFLAGS   = $(base_ldflags)
memleaks_mbedtls_memcheck_SOURCES   = config.h test.c $(UUT)
memleaks_mbedtls_memcheck_CPPFLAGS  = -DENABLE_DEBUG $(mbedtls_cppflags) $(memcheck_cppflags)
endif

TESTS = $(check_PROGRAMS)
