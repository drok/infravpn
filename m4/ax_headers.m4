# This file is part of Autoconf.			-*- Autoconf -*-
# Checking for headers.
#
# Copyright (C) 1988, 1999, 2000, 2001, 2002, 2003, 2004, 2006 Free Software
# Foundation, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# As a special exception, the Free Software Foundation gives unlimited
# permission to copy, distribute and modify the configure scripts that
# are the output of Autoconf.  You need not follow the terms of the GNU
# General Public License when using or distributing such scripts, even
# though portions of the text of Autoconf appear in them.  The GNU
# General Public License (GPL) does govern all other use of the material
# that constitutes the Autoconf program.
#
# Certain portions of the Autoconf source text are designed to be copied
# (in certain cases, depending on the input) into the output of
# Autoconf.  We call these the "data" portions.  The rest of the Autoconf
# source text consists of comments plus executable code that decides which
# of the data portions to output in any given case.  We call these
# comments and executable code the "non-data" portions.  Autoconf never
# copies any of the non-data portions into its output.
#
# This special exception to the GPL applies to versions of Autoconf
# released by the Free Software Foundation.  When you make and
# distribute a modified version of Autoconf, you may extend this special
# exception to the GPL to apply to your modified version as well, *unless*
# your modified version has the potential to copy into its output some
# of the text that was the non-data portion of the version that you started
# with.  (In other words, unless your change moves or copies text from
# the non-data portions to the data portions.)  If your modification has
# such potential, you must delete any notice of this special exception
# to the GPL from your modified version.
#
# Written by David MacKenzie, with help from
# Franc,ois Pinard, Karl Berry, Richard Pixley, Ian Lance Taylor,
# Roland McGrath, Noah Friedman, david d zuhn, and many others.


# Table of contents
#
# 1. Generic tests for headers
# 2. Default includes
# 3. Headers to tests with AC_CHECK_HEADERS
# 4. Tests for specific headers


## ------------------------------ ##
## 1. Generic tests for headers.  ##
## ------------------------------ ##


# AX_CHECK_HEADER(PREFIX, HEADER-FILE, [CONDITION],
#		  [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
#		  [INCLUDE])
# ---------------------------------------------------------
# We are slowly moving to checking headers with the compiler instead
# of the preproc, so that we actually learn about the usability of a
# header instead of its mere presence.  But since users are used to
# the old semantics, they check for headers in random order and
# without providing prerequisite headers.  This macro implements the
# transition phase, and should be cleaned up latter to use compilation
# only.
#
# If INCLUDES is empty, then check both via the compiler and preproc.
# If the results are different, issue a warning, but keep the preproc
# result.
#
# If INCLUDES is `-', keep only the old semantics.
#
# If INCLUDES is specified and different from `-', then use the new
# semantics only.
#
# Differences from AC_CHECK_HEADER:
#
# There are two additional arguments, the 1st and 3rd.
# The 1st argument is a prefix which selects which {prefix}_CFLAGS
# variable to use as CFLAGS when invoking the pre-processor/compiler
# The 3nd argument is a pre-processor conditional, executed
# after the
# header is included, eg, to check that it sets a macro
# appropriately, such as a version value. If the conditional
# evaluates as true, the check is successful (ie, header is
# "compatible"), otherwise, the header is "incompatible" and the
# check fails.
# Also, this function also calls AC_SUBST(PREFIX_CFLAGS), so the caller need not
# call it separately
AC_DEFUN([AX_CHECK_HEADER],
[
ac_save_CFLAGS=$CFLAGS
CFLAGS=$[$1][_CFLAGS]
AC_SUBST([$1][_CFLAGS])
m4_ifval([$3],[m4_case([$6],
	 [],  [_AX_CHECK_HEADER_MONGREL(m4_shift($@))],
	 [-], [_AX_CHECK_HEADER_OLD(m4_shift($@))],
	      [_AX_CHECK_HEADER_NEW(m4_shift(m4_shift($@)))])],
    [AC_CHECK_HEADER([$2],[$4],[$5],[$6])])
CFLAGS=$ac_save_CFLAGS
])# AX_CHECK_HEADER

# _AC_CHECK_HEADER_MONGREL(HEADER-FILE, [CONDITION],
#			   [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
#			   [INCLUDES = DEFAULT-INCLUDES])
# ------------------------------------------------------------------
# Check using both the compiler and the preprocessor.  If they disagree,
# warn, and the preproc wins.
#
# This is not based on _AC_CHECK_HEADER_NEW and _AC_CHECK_HEADER_OLD
# because it obfuscate the code to try to factor everything, in particular
# because of the cache variables, and the `checking...' messages.
m4_define([_AX_CHECK_HEADER_MONGREL],
[AS_VAR_PUSHDEF([ac_Header], [ac_cv_header_$1])
AS_VAR_SET_IF([ac_Header],
	      [AC_CACHE_CHECK([for $1 ($2)], [ac_Header], [])],
	      [# Is the header compilable and compatible?
AC_MSG_CHECKING([$1 usability])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([AC_INCLUDES_DEFAULT([$5])
@%:@include <$1>
@%:@if !($2)
@%:@error incompatible with '$2'
@%:@endif
])],
		  [ac_header_compiler=yes],
		  [ac_header_compiler=no])
AC_MSG_RESULT([$ac_header_compiler])

# Is the header present?
AC_MSG_CHECKING([$1 presence])
AC_PREPROC_IFELSE([AC_LANG_SOURCE([@%:@include <$1>
@%:@if !($2)
@%:@error incompatible with '$2'
@%:@endif
])],
		  [ac_header_preproc=yes],
		  [ac_header_preproc=no])
AC_MSG_RESULT([$ac_header_preproc])

# So?  What about this header?
case $ac_header_compiler:$ac_header_preproc:$ac_[]_AC_LANG_ABBREV[]_preproc_warn_flag in
  yes:no: )
    AC_MSG_WARN([$1: accepted by the compiler, rejected by the preprocessor!])
    AC_MSG_WARN([$1: proceeding with the compiler's result])
    ;;
  no:yes:* )
    AC_MSG_WARN([$1: present but not compatible '$2'])
    ;;
esac
AC_CACHE_CHECK([for $1 ($2)], [ac_Header],
	       [AS_VAR_SET([ac_Header], [$ac_header_compiler])])
])
AS_VAR_IF([ac_Header], [yes], [$3], [$4])[]
AS_VAR_POPDEF([ac_Header])
])# _AC_CHECK_HEADER_MONGREL

# _AC_CHECK_HEADER_NEW(HEADER-FILE, CONDITION,
#		       [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
#		       [INCLUDES = DEFAULT-INCLUDES])
# --------------------------------------------------------------
# Check the compiler accepts HEADER-FILE.  The INCLUDES are defaulted.
m4_define([_AX_CHECK_HEADER_NEW],
[AS_VAR_PUSHDEF([ac_Header], [ac_cv_header_$1])
AC_CACHE_CHECK([for $1 ($2)], [ac_Header],
	       [AC_COMPILE_IFELSE([AC_LANG_SOURCE([AC_INCLUDES_DEFAULT([$5])
@%:@include <$1>
@%:@if !($2)
#error incompatible with '$2'
@%:@endif
])],
				  [AS_VAR_SET([ac_Header], [yes])],
				  [AS_VAR_SET([ac_Header], [no])])])
AS_VAR_IF([ac_Header], [yes], [$3], [$4])[]
AS_VAR_POPDEF([ac_Header])
])# _AC_CHECK_HEADER_NEW

# _AC_CHECK_HEADER_OLD(HEADER-FILE, CONDITION,
#		       [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# --------------------------------------------------------------
# Check the preprocessor accepts HEADER-FILE.
m4_define([_AX_CHECK_HEADER_OLD],
[AS_VAR_PUSHDEF([ac_Header], [ac_cv_header_$1])
AC_CACHE_CHECK([for $1 ($2)], [ac_Header],
	       [AC_PREPROC_IFELSE([AC_LANG_SOURCE([@%:@include <$1>
@%:@if !($2)
#error incompatible with '$2'
@%:@endif
])],
					 [AS_VAR_SET([ac_Header], [yes])],
					 [AS_VAR_SET([ac_Header], [no])])])
AS_VAR_IF([ac_Header], [yes], [$3], [$4])[]
AS_VAR_POPDEF([ac_Header])
])# _AC_CHECK_HEADER_OLD

