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
# Functionality/behaviour tests. Typically use the cmocka library for assertion checking.
TEST_EXTENSIONS = .test

# Build will be run with [valgrind --tool=memcheck](https://valgrind.org/docs/manual/mc-manual.html)
TEST_EXTENSIONS += .memcheck

MEMCHECK_LOG_COMPILER = $(VALGRIND)
MEMCHECK_LOG_FLAGS = --tool=memcheck \
	--error-exitcode=1 \
	--leak-check=yes \
	--undef-value-errors=yes \
	--track-origins=yes

memcheck_cflags = -g -fno-inline
memcheck_cppflags = -DNO_CMOCKA_MEMCHECK

# The test is a configuration file. It will be run through a configuration checker (TODO: implement this testdriver)
TEST_EXTENSIONS += .conf

# Performance test. Check that the time complexity (O(n)) is acceptable. (TODO: implement this testdriver)
TEST_EXTENSIONS += .perf
