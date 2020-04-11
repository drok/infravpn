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

if IMPLEMENTED_tls_crypt_2_4
activation_CPPFLAGS += -DIMPLEMENTATION_2_4
else

if IMPLEMENTED_tls_crypt_2_5
activation_CPPFLAGS += -DIMPLEMENTATION_2_5
else

endif
endif

# TEST_SUITE_LOG=blah.log

check_PROGRAMS = protocol.tls_crypt.test \
		ndebug.test \
		debug.test

TESTS = $(check_PROGRAMS)

base_cflags = @CMOCKA_CFLAGS@ $(OPTIONAL_CRYPTO_CFLAGS)
base_libs = @CMOCKA_LIBS@ $(OPTIONAL_CRYPTO_LIBS)
base_ldflags = -Wl,--wrap=buffer_read_from_file \
		-Wl,--wrap=buffer_write_file \
		-Wl,--wrap=parse_line \
		-Wl,--wrap=rand_bytes
base_cppflags = @TEST_CPPFLAGS@ \
		-include $(testlib_srcdir)/moerror.h \
		$(activation_CPPFLAGS) \
		-I$(openvpn_srcdir) \
		-I$(compat_srcdir)

# Override $top_build_dir/config.h with local version so some defines can be
# specified as CPPFLAGS
BUILT_SOURCES = config.h
CLEANFILES = config.h
config.h : $(top_builddir)/config.h
	$(SED) -r '/#define ENABLE_(DEBUG)/d' $< >$@

protocol_tls_crypt_test_CFLAGS        = $(base_cflags)
protocol_tls_crypt_test_LDADD         = $(base_libs)
protocol_tls_crypt_test_LDFLAGS       =	$(base_ldflags)
protocol_tls_crypt_test_SOURCES       = test.c $(UUT)
protocol_tls_crypt_test_CPPFLAGS      = $(base_cppflags)

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
ndebug_test_CFLAGS    = $(base_cflags)
ndebug_test_LDADD     = $(base_libs)
ndebug_test_LDFLAGS   = $(base_ldflags)
ndebug_test_SOURCES   = test.c $(UUT)
ndebug_test_CPPFLAGS  = -DNDEBUG $(base_cppflags)

# Enabled debugging is not supposed to modify behaviour, but sometimes
# active code is forgotten surrounded by #test ENABLE_DEBUG
# this test may help catch those.
debug_test_CFLAGS    = $(base_cflags)
debug_test_LDADD     = $(base_libs)
debug_test_LDFLAGS   = $(base_ldflags)
debug_test_SOURCES   = test.c $(UUT)
debug_test_CPPFLAGS  = -DENABLE_DEBUG $(base_cppflags)
