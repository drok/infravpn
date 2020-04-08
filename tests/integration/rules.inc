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
# Integration build flavors. Each flavor can be tested by a different
# runner/log_compiler, defined as {FLAVOR}_LOG_COMPILER in a subdir from here

# Test a binary as Multi Server
TEST_EXTENSIONS = .server

# Test a binary as Multi Client
TEST_EXTENSIONS += .client

# Test a binary as peer-2-peer
TEST_EXTENSIONS += .p2p

# Utility build (standalone key generators, etc)
TEST_EXTENSIONS += .util


AM_TESTS_ENVIRONMENT =

if IMPLEMENTED_tls_crypt_2_5
AM_TESTS_ENVIRONMENT += IMPLEMENTED_tls_crypt_2_5=1
endif

if ENABLE_UNITTESTS_ALL

# Use the package's config-version.h from the top-build directory.


if GIT_CHECKOUT
BUILT_SOURCES += config-version.h
CLEANFILES += config-version.h

config-version.h: $(top_srcdir)/.git/logs/HEAD
	@CONFIGURE_GIT_CHFILES="`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) diff-files --name-status -r --ignore-submodules --quiet -- || echo \"+\"`"; \
	CONFIGURE_GIT_UNCOMMITTED="`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) diff-index --cached  --quiet --ignore-submodules HEAD || echo \"*\"`"; \
	CONFIGURE_GIT_REVISION="`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) rev-parse --symbolic-full-name HEAD | cut -d/ -f3-`/`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) rev-parse --short=16 HEAD`"; \
	echo "#define CONFIGURE_GIT_REVISION \"$${CONFIGURE_GIT_REVISION}\"" > $@-t; \
	echo "#define CONFIGURE_GIT_FLAGS \"$${CONFIGURE_GIT_CHFILES}$${CONFIGURE_GIT_UNCOMMITTED}\"" >> $@-t && mv $@-t $@
endif
endif

# target for building without running the tests
.PHONY: all_tests
all_tests: $(check_PROGRAMS)

# automake 1.13.1d to 1.14.1 contain an E2BIG bug (http://debbugs.gnu.org/18744)
# in the detection of gnu make, instroduced at automake 3de278 (1.13.1d), and
# fixed e7c14d (1.15)
# This definition of am__is_gnu_make overrides the buggy version in that range
# of automakes. For versions below the 1.13.1d this define will be unused,
# and benign.
# It this definition still has a bug, it will overwrite any automake bugfixes,
# and whoever runs into it, should replace it with the best version of the
# detection scriptlet at that future time.
# As of this writing, this scriptlet is current in automake/master(ae911) and
# the latest release (1.16.2)
am__is_gnu_make = { \
  if test -z '$(MAKELEVEL)'; then \
    false; \
  elif test -n '$(MAKE_HOST)'; then \
    true; \
  elif test -n '$(MAKE_VERSION)' && test -n '$(CURDIR)'; then \
    true; \
  else \
    false; \
  fi; \
}
