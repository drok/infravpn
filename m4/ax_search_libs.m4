# This file is part of Autoconf.                       -*- Autoconf -*-
# Checking for libraries.
# Copyright (C) 1992, 1993, 1994, 1995, 1996, 1998, 1999, 2000, 2001,
# 2002, 2003, 2004, 2005, 2006, 2008 Free Software Foundation, Inc.

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
# Written by Radu Hociung, based on AC_SEARCH_LIBS by David MacKenzie,
# Franc,ois Pinard, Karl Berry, Richard Pixley, Ian Lance Taylor,
# Roland McGrath, Noah Friedman, david d zuhn, and many others.

# Table of contents
#
# 1. Generic tests for libraries

## --------------------------------- ##
## 1. Generic tests for libraries.## ##
## --------------------------------- ##



# AX_SEARCH_LIBS(LIBVAR, FUNCTION, SEARCH-LIBS,
#                [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
#                [OTHER-LIBRARIES])
# --------------------------------------------------------
# Search for a library defining FUNC, if it's not already available.
# Works like AC_SEARCH_LIBS, except the 1st arg is the name of the xxx_LIBS variable to prepend
# the results to. It saves having to check if the result is "none required" before appending to
# xxx_LIBS
# AC_SUBST is automatically called for xxx_LIB
AC_DEFUN([AX_SEARCH_LIBS],
[AS_VAR_PUSHDEF([ac_Search], [ac_cv_search_$2])
AC_CACHE_CHECK([for library containing $2], [ac_Search],
[ac_func_search_save_LIBS=$LIBS 
ac_func_search_save_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS $[$1][_CFLAGS]"
AC_LANG_CONFTEST([AC_LANG_CALL([], [$2])])
for ac_lib in '' $3; do
  if test -z "$ac_lib"; then
    ac_res="none required"
    LIBS="$[$1][_LIBS]"
  else
    ac_res=-l$ac_lib
    LIBS="-l$ac_lib $5 $[$1][_LIBS]"
  fi
  AC_LINK_IFELSE([], [AS_VAR_SET([ac_Search], [$ac_res])])
  AS_VAR_SET_IF([ac_Search], [break])
done
AS_VAR_SET_IF([ac_Search], , [AS_VAR_SET([ac_Search], [no])])
rm conftest.$ac_ext
CFLAGS=$ac_func_search_save_CFLAGS
LIBS=$ac_func_search_save_LIBS])
ac_res=AS_VAR_GET([ac_Search])
AS_IF([test "$ac_res" != no],
  [test "$ac_res" = "none required" || [$1][_LIBS]="$ac_res $[$1][_LIBS]"
  $4],
      [$5])
AC_SUBST([$1][_LIBS])
AS_VAR_POPDEF([ac_Search])
])

