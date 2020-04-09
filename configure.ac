dnl  Tests   -- A test infrastructure for backwards-compatible testing
dnl
dnl  Copyright (C) 2020 Radu Hociung <radu.tests@ohmi.org>
dnl
dnl  This program is free software; you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License as published by
dnl  the Free Software Foundation; either version 2 of the License, or
dnl  (at your option) any later version.
dnl
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program (see the file COPYING included with this
dnl  distribution); if not, write to the Free Software Foundation, Inc.,
dnl  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

AC_INIT([TESTS], [1.0.0], [tests@ohmi.org], [tests])
AC_CONFIG_AUX_DIR([.])
AM_CONFIG_HEADER(config.h)
AC_CONFIG_SRCDIR(syshead.h)
AC_CONFIG_MACRO_DIR([m4])

# Build tools ------------------------------------------------------------------
AC_PROG_GREP
AM_PROG_CC_C_O
AC_PATH_PROG([VALGRIND], [valgrind], [echo Failing test because Valgrind is not installed && false])
AC_PROG_SED

AC_ARG_VAR([GIT], [path to git utility])
AC_CHECK_PROGS([GIT], [git]) # optional

# Compiler characteristics -----------------------------------------------------
AX_CPP_VARARG_MACRO_ISO
AX_CPP_VARARG_MACRO_GCC

# GIT versioning Detection -----------------------------------------------------
AC_MSG_CHECKING([git checkout])
GIT_CHECKOUT="no"
if test -n "${GIT}" -a -d "${srcdir}/.git"; then
        AC_DEFINE([HAVE_CONFIG_VERSION_H], [1], [extra version available in config-version.h])
        GIT_CHECKOUT="yes"
fi
AC_MSG_RESULT([${GIT_CHECKOUT}])

AM_CONDITIONAL([GIT_CHECKOUT], [test "${GIT_CHECKOUT}" = "yes"])

# Output/generated files -------------------------------------------------------
AC_CONFIG_FILES([
    Makefile 
    tests/Makefile
])

# ######################## Tree-Structure Versioning ###########################
dnl # As the project evolves, the source may be reorganized repeatedly, with files
dnl # moved or renamed, directories created or removed, etc.
dnl # In order to inform the test suite (which must work on any source structure),
dnl # a $tree_structure_version variable is tracked. Based on this variable,
dnl # the testsuite defines the source paths appropriately.
dnl # When the source is reorganized next, this variable should be explicitly set,
dnl # in and tests/srcpaths.inc file in the tests repo should be updated appropriately.
dnl # Adding new components (eg. src/plugins), without moving existing sources, is
dnl # not reorganizing, so a new TREE_VERSION conditional is not needed. In this case,
dnl # simply add "plugins_srcdir=..." to tests/srcpaths.inc under the current
dnl # TREE_VERSION conditional.
# The early versions of the project did not have this infrastructure, so a
# $tree_structure_version is detected.

# Legacy trees have to be detected.
if test "$ac_unique_file" = "syshead.h" ; then
 tree_structure_version="2.0"
elif test "$ac_unique_file" = "src/openvpn/syshead.h" ; then
  if expr "$ac_config_headers" : '.* include/openvpn-plugin.h' >/dev/null ; then
    tree_structure_version="2.4"
  else
    tree_structure_version="2.3"
  fi
fi
# Do not add more. New trees set the tree_structure_version directly, below.

# tree_structure_version="5.7"
AM_CONDITIONAL([TREE_VERSION_2_0], [test "$tree_structure_version" = "2.0"])
AM_CONDITIONAL([TREE_VERSION_2_3], [test "$tree_structure_version" = "2.3"])
AM_CONDITIONAL([TREE_VERSION_2_4], [test "$tree_structure_version" = "2.4"])
AM_CONDITIONAL([TREE_VERSION_FUTURE_EXAMPLE], [test "$tree_structure_version" = "5.7"])
# #################### END Tree-Structure Versioning ###########################

# ######################## Feature Implementations ############################
# 1. When work a new feature starts, add both an IMPLEMENTED_{FEATURE}
#    conditional here, and a UNIT_TESTED_{FEATURE} further below, both set to
#    [false].
# 2. Commit the two conditionals to both the source repo and the test repo.
# 3. Implement the unit test. Toggle UNIT_TESTED_{FEATURE} to [true]
# 4. Commit the unit test and the UNIT_TESTED_{FEATURE} conditional to the
#    test repo.
# 5. Implement the feature. Toggle IMPLEMENTED_{FEATURE} to [true]
# 6. Commit the implementation and the IMPLEMENTED_{FEATURE} conditional *ONLY*
#    to the source repo.
# 7. Test, debug, improve the unit test until coverage is good enough.
# 8. Commit implementation fixes to the source tree.
# 9. Commit unit test fixes to the test tree.
# 10. Merge unit tree into implementation tree.
# 11. When features are obsolete/removed, toggle only IMPLEMENTED_{FEATURE} to
#     false, remove the integration, and commit. Do not remove the unit test,
#     it is still useful to test and maintain the obsolete feature in old
#     releases. The test will no longer run on new releases, where the FEATURE
#     is no longer IMPLEMENTED_{}.
#
# Adding tests for pre-existing features. The implementations must be detected,
# cannot be assumed either false nor true. Then, the unit-test will be
# automatically disabled when merged into source trees pre-dating the feature's
# introduction.
# eg, check that the implementation source file exists in the same directory as
# the AC_CONFIG_SRCDIR() item above:
# AM_CONDITIONAL([IMPLEMENTED_base64], [test -f $(dirname "$srcdir/$ac_unique_file")/base64.c])
#
# IMPORTANT: If you are changing an older branch, such that the "grep-ed"
# match signature will no longer match, do not update the signature.
# Instead, replace it with "AM_CONDITIONAL([IMPLEMENTED_xxx_Y_Z], [true])",
# and commit it to the source tree, in the same commit as your source changes,
# but *not* the tests repo.
# This way, if your bug fix gets merged into another branch, the detection
# will be updated as well, and the test suite will continue working in that
# destination branch.
#
# At the end of this process, the source repo/branch (eg, "master") will contain
# a tested implementation and the unit tests, and the test repo ("tests") will
# contain only the unit tests, in a form that can be merged to any branch of the
# source tree, including old releases, to backtest old code with the newest
# tests.
# In the unit test tree, add the following to test a feature in a backwards
# compatible way (ie, skipping test where the feature is not implemented);
# in tests/Makefile.am:
#
# if UNIT_TESTED_feature
# SUBDIRS += unit/feature
# endif

AM_CONDITIONAL([IMPLEMENTED_base64_2_0],
    [test -f $(dirname "$srcdir/$ac_unique_file")/base64.c &&
    ${GREP} '^base64_decode(const char \*str, void \*data)$' $(dirname "$srcdir/$ac_unique_file")/base64.c >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_base64_2_2],
    [test -f $(dirname "$srcdir/$ac_unique_file")/base64.c &&
    ${GREP} '^base64_decode(const char \*str, void \*data, int size)$' $(dirname "$srcdir/$ac_unique_file")/base64.c >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_base64_2_3],
    [test -f $(dirname "$srcdir/$ac_unique_file")/base64.c &&
    ${GREP} '^openvpn_base64_decode(const char \*str, void \*data, int size)$' $(dirname "$srcdir/$ac_unique_file")/base64.c >/dev/null])

AM_CONDITIONAL([IMPLEMENTED_tls_crypt_2_4],
    [test -f $(dirname "$srcdir/$ac_unique_file")/tls_crypt.c &&
    ! ${GREP} '^tls_crypt_v2_write_client_key_file(const char \*filename$' $(dirname "$srcdir/$ac_unique_file")/tls_crypt.c >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_tls_crypt_2_5],
    [test -f $(dirname "$srcdir/$ac_unique_file")/tls_crypt.c &&
    ${GREP} '^tls_crypt_v2_write_client_key_file(const char \*filename$' $(dirname "$srcdir/$ac_unique_file")/tls_crypt.c >/dev/null])

AM_CONDITIONAL([IMPLEMENTED_rfc4821], [false])

AM_CONDITIONAL([IMPLEMENTED_buffer_2_0],
    [test -f $(dirname "$srcdir/$ac_unique_file")/buffer.c &&
    ${GREP} '^char_class (const char c, const unsigned int flags)$' $(dirname "$srcdir/$ac_unique_file")/buffer.c >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_buffer_2_2],
    [test -f $(dirname "$srcdir/$ac_unique_file")/buffer.c &&
    ${GREP} '^char_class (const unsigned char c, const unsigned int flags)$' $(dirname "$srcdir/$ac_unique_file")/buffer.c >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_buffer_2_3],
    [test -f $(dirname "$srcdir/$ac_unique_file")/buffer.c &&
    ${GREP} '^buf_puts(struct buffer \*buf, const char \*str)$' $(dirname "$srcdir/$ac_unique_file")/buffer.c >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_buffer_2_4],
    [test -f $(dirname "$srcdir/$ac_unique_file")/buffer.c &&
    ${GREP} '^gc_addspecial(void \*addr, void(free_function)(void \*), struct gc_arena \*a)$' $(dirname "$srcdir/$ac_unique_file")/buffer.c >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_buffer_2_4_5],
    [test -f $(dirname "$srcdir/$ac_unique_file")/buffer.h &&
    ${GREP} '^void buffer_list_push(struct buffer_list \*ol, const char \*str);$' $(dirname "$srcdir/$ac_unique_file")/buffer.h >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_buffer_2_5],
    [test -f $(dirname "$srcdir/$ac_unique_file")/buffer.c &&
    ${GREP} '^buffer_write_file(const char \*filename, const struct buffer \*buf)$' $(dirname "$srcdir/$ac_unique_file")/buffer.c])

AM_CONDITIONAL([IMPLEMENTED_mtu_2_0],
    [test -f $(dirname "$srcdir/$ac_unique_file")/mtu.c &&
    ${GREP} '^frame_set_mtu_dynamic' $(dirname "$srcdir/$ac_unique_file")/mtu.c])
AM_CONDITIONAL([IMPLEMENTED_mtu_2_4],
    [test -f $(dirname "$srcdir/$ac_unique_file")/mtu.c &&
    ${GREP} '^frame_init_mssfix' $(dirname "$srcdir/$ac_unique_file")/mtu.c])
AM_CONDITIONAL([IMPLEMENTED_mtu2], [false])

AM_CONDITIONAL([IMPLEMENTED_sitnl_2_5], [test -f $(dirname "$srcdir/$ac_unique_file")/networking_sitnl.c])

# #################### End Feature Implementations ############################

# ######################## Buildable Packages #################################
AM_CONDITIONAL([INTEGRATED_openvpn_2_0], [expr "$PACKAGE_STRING" : 'OpenVPN 2\.0\.' >/dev/null])
AM_CONDITIONAL([INTEGRATED_openvpn_2_1], [expr "$PACKAGE_STRING" : 'OpenVPN 2\.1\.' >/dev/null])
AM_CONDITIONAL([INTEGRATED_openvpn_2_2], [expr "$PACKAGE_STRING" : 'OpenVPN 2\.2\.' >/dev/null])
AM_CONDITIONAL([INTEGRATED_openvpn_2_3], [expr "$PACKAGE_STRING" : 'OpenVPN 2\.3\.' >/dev/null])
AM_CONDITIONAL([INTEGRATED_openvpn_le_2_3], [[expr "$PACKAGE_STRING" : 'OpenVPN 2\.[0-3]\.' >/dev/null]])
AM_CONDITIONAL([INTEGRATED_openvpn_2_4], [expr "$PACKAGE_STRING" : 'OpenVPN 2\.4\.' >/dev/null])
AM_CONDITIONAL([INTEGRATED_openvpn_2_5], [expr "$PACKAGE_STRING" : 'OpenVPN 2\.5\.' >/dev/null])

AM_CONDITIONAL([INTEGRATED_ovpn], [expr "$PACKAGE_STRING" : 'OVPN ' >/dev/null])
AM_CONDITIONAL([INTEGRATED_ovpn_1_0], [expr "$PACKAGE_STRING" : 'OVPN 1\.0\.' >/dev/null])

AC_CONFIG_FILES(tests/integration/does-it-build/Makefile)
# ######################## End Buildable Packages #############################

# ####################### Feature Unit Tests ##################################
# Once a test is implemented for a feature, toggle UNIT_TESTED_{feature} to true
# Never remove or turn UNIT_TESTED_{feature} to false after it's turned true.
# Removing it would break old builds ("Makefile.am:xxx: UNIT_TESTED_{feature}
# does not appear in AM_CONDITIONAL") when the test branch is merged there,
# as would turning it false (unresolved symbols at link time).
# In the source tree, add the following to include a feature:
# In src/openvpn/Makefile.am
#
#   if UNIT_TESTED_feature
#    openvpn_SOURCES += feature.c feature.h
#   endif

AM_COND_IF([IMPLEMENTED_base64_2_0], [implemented=yes])
AM_COND_IF([IMPLEMENTED_base64_2_2], [implemented=yes])
AM_COND_IF([IMPLEMENTED_base64_2_3], [implemented=yes])
AS_IF([test "$implemented" = "yes"], [AC_CONFIG_FILES(tests/unit/base64/Makefile)])
AM_CONDITIONAL([UNIT_TESTED_base64], [test "$implemented" = "yes" && unset implemented])

AM_COND_IF([IMPLEMENTED_tls_crypt_2_4], [implemented=yes])
AM_COND_IF([IMPLEMENTED_tls_crypt_2_5], [implemented=yes])
#
# NOTE: It is wrong to not test the tls_crypt implementation if the current build
# configuration does not enable it. I am only demonstrating a straight-up port
# of a unit test from tests/unit_tests to tests/unit. This is the old test-suite
# behaviour, ie, if a feature is not used, it's not tested. If it's broken
# by a patch, the breakage would only be noticed by whoever builds it with the
# broken feature enable.
# The next commit demonstrates how the tests/unit framework tests all the
# implemented features, regardless if they are used or not in the build, in
# "maintainer
#
AS_IF([test "$implemented" = "yes"], [AC_CONFIG_FILES(tests/unit/tls_crypt/Makefile)])
AM_CONDITIONAL([UNIT_TESTED_tls_crypt], [test "$implemented" = "yes" && unset implemented])

AM_COND_IF([IMPLEMENTED_rfc4821], [implemented=yes])
AS_IF([test "$implemented" = "yes"], [AC_CONFIG_FILES(tests/unit/rfc4821/Makefile)])
AM_CONDITIONAL([UNIT_TESTED_rfc4821], [test "$implemented" = "yes" && unset implemented])

AM_COND_IF([IMPLEMENTED_buffer_2_0], [implemented=yes])
AM_COND_IF([IMPLEMENTED_buffer_2_2], [implemented=yes])
AM_COND_IF([IMPLEMENTED_buffer_2_3], [implemented=yes])
AM_COND_IF([IMPLEMENTED_buffer_2_4], [implemented=yes])
AM_COND_IF([IMPLEMENTED_buffer_2_5], [implemented=yes])
AS_IF([test "$implemented" = "yes"], [AC_CONFIG_FILES(tests/unit/buffer/Makefile)])
AM_CONDITIONAL([UNIT_TESTED_buffer], [test "$implemented" = "yes" && unset implemented])

AM_COND_IF([IMPLEMENTED_mtu_2_0], [implemented=yes])
AM_COND_IF([IMPLEMENTED_mtu_2_4], [implemented=yes])
AM_COND_IF([IMPLEMENTED_mtu2],    [implemented=yes])
AS_IF([test "$implemented" = "yes"], [AC_CONFIG_FILES(tests/unit/mtu/Makefile)])
AM_CONDITIONAL([UNIT_TESTED_mtu], [test "$implemented" = "yes" && unset implemented])

AM_COND_IF([IMPLEMENTED_sitnl_2_5], [implemented=yes])
AM_CONDITIONAL([UNIT_TESTED_sitnl], [test "$implemented" = "yes" && unset implemented])
# ################### End Feature Unit Tests ##################################

AC_ARG_ENABLE(
     [unit-tests],
     [AS_HELP_STRING([--disable-unit-tests],
                     [Disables building and running the unit tests suite. By default, only
                     the package configuration is tested.])
AS_HELP_STRING([--enable-unit-tests=all],
                     [Enables the full-test suite (maintainer mode). 
                      Requires all possible dependencies to be installed,
                      and tests all implemented code, whether activated by the
                      package configuration or not.
                      Mainly useful to the maintainers.])]
)

AM_CONDITIONAL([ENABLE_UNITTESTS], [test "${enable_unit_tests}" != "no"])
AM_CONDITIONAL([ENABLE_UNITTESTS_ALL], [test "${enable_unit_tests}" = "all"])
AC_ARG_VAR([TEST_CPPFLAGS], [Preprocessor flags applied to all C unit tests])
AC_ARG_VAR([TEST_CFLAGS], [Compiler flags applied to all C unit tests])
AC_ARG_VAR([TEST_LDFLAGS], [Linker flags applied to all C unit tests])

ADD_CFLAGS(TEST, [-Werror=implicit-function-declaration])
ADD_CFLAGS(TEST, [-Werror=unused-but-set-variable])
ADD_CFLAGS(TEST, [-Werror=format])
ADD_CFLAGS(TEST, [-Werror=maybe-uninitialized])

AC_ARG_VAR([XFAIL_TESTS], [Tests expected to fail])

AS_IF([test "${enable_unit_tests}" != "no"], [
    # Check if cmocka is available - needed for unit testing
    PKG_CHECK_MODULES(
            [CMOCKA], [cmocka],,
            [AC_MSG_ERROR([cmocka (required for unit testing) not found. Install it or --disable-unit-tests])]
    )

    AX_SEARCH_LIBS(MATH, [log2], [m])
])
AC_SUBST([MATH_LIBS])

AC_OUTPUT
