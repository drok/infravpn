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
# This is tests/srcpaths.inc
# The Source Tree structure is defined in configure.ac
# When the source tree is reorganized, add a new conditional define there
# and add a new set of paths here.

testlib_srcdir = $(top_srcdir)/tests/common

if TREE_VERSION_2_0
    openvpn_includedir = $(top_srcdir)/include
    openvpn_srcdir = $(top_srcdir)
endif

if TREE_VERSION_2_3
    openvpn_includedir = $(top_srcdir)/include
    openvpn_srcdir = $(top_srcdir)/src/openvpn
    compat_srcdir = $(top_srcdir)/src/compat
endif

if TREE_VERSION_FUTURE_EXAMPLE
    openvpn_includedir = $(top_srcdir)/new-path/to/include
    openvpn_srcdir = $(top_srcdir)/new-path/to/openvpn
    compat_srcdir = $(top_srcdir)/new-path/to/compat

    # New component paths should not be added retroactively to older
    # TREE_VERSION_*, where they did do not exist.
    # If a component is backported, then yes, add it retroactively, so the
    # corresponding unit tests can find the implementation.
    newcomponent_srcdir = $(top_srcdir)/src/where-is-the-new-component
endif

# Override default libs resulting from configure.ac
# In tests, all needed libraries must be specifically added to LDADD
LIBS =

if ENABLE_UNITTESTS_ALL

# Override $top_build_dir/config.h with local version so some defines can be
# specified as CPPFLAGS
BUILT_SOURCES = config.h
CLEANFILES = config.h
null =
space = $(null) #
config.h : $(top_builddir)/config.h Makefile
	$(SED) -r "/#define ($(subst $(space),|,$(strip $(mutators))))/d" $< >$@

endif
