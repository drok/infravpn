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
