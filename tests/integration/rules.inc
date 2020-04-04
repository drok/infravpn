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

# Multi Server-only
TEST_EXTENSIONS = .server

# Multi Server/client combination
TEST_EXTENSIONS += .combo

# Multi Client-only
TEST_EXTENSIONS += .client

# Non-Multi build
TEST_EXTENSIONS += .p2p

# Utility build (standalone key generators, etc)
TEST_EXTENSIONS += .util
