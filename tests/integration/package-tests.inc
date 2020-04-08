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

TEST_EXTENSIONS = .Tcrypto
TCRYPTO_LOG_COMPILER = $(top_srcdir)/tests/integration/does-it-build/t_lpback.sh

if ENABLE_UNITTESTS

AM_TESTS_ENVIRONMENT =
TESTS =
XFAIL_TESTS = @XFAIL_TESTS@

if IMPLEMENTED_tls_crypt_2_5
AM_TESTS_ENVIRONMENT += IMPLEMENTED_tls_crypt_2_5=1
endif


if ENABLE_CRYPTO

if INTEGRATED_openvpn
TESTS += test-crypto/openvpn.Tcrypto
endif

if INTEGRATED_ovpn
TESTS += test-crypto/openvpn.Tcrypto
endif

test-crypto/%.Tcrypto:: %
	$(MKDIR_P) $(dir $@)
	$(LN_S) ../$< $@ || :
endif

endif

