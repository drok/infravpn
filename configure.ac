dnl  OpenVPN -- An application to securely tunnel IP networks
dnl             over a single UDP port, with support for SSL/TLS-based
dnl             session authentication and key exchange,
dnl             packet encryption, packet authentication, and
dnl             packet compression.
dnl
dnl  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
dnl  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
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

m4_include(version.m4)
AC_INIT([PRODUCT_NAME], [PRODUCT_VERSION], [PRODUCT_BUGREPORT], [PRODUCT_TARNAME])
m4_include(compat.m4)
AC_DEFINE([OPENVPN_VERSION_RESOURCE], [PRODUCT_VERSION_RESOURCE], [Version in windows resource format])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/openvpn/syshead.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE(foreign parallel-tests) dnl NB: Do not [quote] this parameter.
AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

# Required Library Versions ----------------------------------------------------
required_polarssl_ver_min=1.3.8
required_polarssl_ver_min_hex=0x01030800
required_polarssl_ver_max=1.4.0
required_polarssl_ver_max_hex=0x01040000

required_openssl_ver_min=0.9.6
required_openssl_ver_min_hex=0x00906000L

required_pkcs11_ver_min=1.11

# Human-readable program names -------------------------------------------------
PolarSSL="PolarSSL (>=$required_polarssl_ver_min <$required_polarssl_ver_max)"
OpenSSL="OpenSSL (>=$required_openssl_ver_min)"
PKCS11_HELPER="libpkcs11-helper (>=$required_pkcs11_ver_min)"

# Package Configuration --------------------------------------------------------
AC_ARG_ENABLE(
	[lzo],
	[AS_HELP_STRING([--disable-lzo], [disable LZO compression support @<:@default=yes@:>@])],
	,
	[enable_lzo="yes"]
)

AC_ARG_ENABLE(
	[lzo-stub],
	[AS_HELP_STRING([--enable-lzo-stub], [don't compile LZO compression support but still allow limited interoperability with LZO-enabled peers @<:@default=no@:>@])],
	,
	[enable_lzo_stub="no"]
)

AC_ARG_ENABLE(
	[crypto],
	[AS_HELP_STRING([--disable-crypto], [disable crypto support @<:@default=yes@:>@])],
	,
	[enable_crypto="yes"]
)

AC_ARG_ENABLE(
	[ofb-cfb],
	[AS_HELP_STRING([--disable-ofb-cfb], [disable support for OFB and CFB cipher modes @<:@default=yes@:>@])],
	,
	[enable_crypto_ofb_cfb="yes"]
)

AC_ARG_ENABLE(
	[ssl],
	[AS_HELP_STRING([--disable-ssl], [disable SSL support for TLS-based key exchange @<:@default=yes@:>@])],
	,
	[enable_ssl="yes"]
)

AC_ARG_ENABLE(
	[x509-alt-username],
	[AS_HELP_STRING([--enable-x509-alt-username], [enable the --x509-username-field feature @<:@default=no@:>@])],
	,
	[enable_x509_alt_username="no"]
)

AC_ARG_ENABLE(
	[multi],
	[AS_HELP_STRING([--disable-multi], [disable client/server support (--mode server + client mode) @<:@default=yes@:>@])],
	,
	[enable_multi="yes"]
)

AC_ARG_ENABLE(
	[server],
	[AS_HELP_STRING([--disable-server], [disable server support only (but retain client support) @<:@default=yes@:>@])],
	,
	[enable_server="yes"]
)

AC_ARG_ENABLE(
	[plugins],
	[AS_HELP_STRING([--disable-plugins], [disable plug-in support @<:@default=yes@:>@])],
	,
	[enable_plugins="yes"]
)

AC_ARG_ENABLE(
	[management],
	[AS_HELP_STRING([--disable-management], [disable management server support @<:@default=yes@:>@])],
	,
	[enable_management="yes"]
)

AC_ARG_ENABLE(
	[pkcs11],
	[AS_HELP_STRING([--enable-pkcs11], [enable pkcs11 support @<:@default=no@:>@])],
	,
	[enable_pkcs11="no"]
)

AC_ARG_ENABLE(
	[socks],
	[AS_HELP_STRING([--disable-socks], [disable Socks support @<:@default=yes@:>@])],
	,
	[enable_socks="yes"]
)

AC_ARG_ENABLE(
	[http-proxy],
	[AS_HELP_STRING([--disable-http-proxy], [disable HTTP proxy support @<:@default=yes@:>@])],
	,
	[enable_http_proxy="yes"]
)

AC_ARG_ENABLE(
	[fragment],
	[AS_HELP_STRING([--disable-fragment], [disable internal fragmentation support (--fragment) @<:@default=yes@:>@])],
	,
	[enable_fragment="yes"]
)

AC_ARG_ENABLE(
	[multihome],
	[AS_HELP_STRING([--disable-multihome], [disable multi-homed UDP server support (--multihome) @<:@default=yes@:>@])],
	,
	[enable_multihome="yes"]
)

AC_ARG_ENABLE(
	[port-share],
	[AS_HELP_STRING([--disable-port-share], [disable TCP server port-share support (--port-share) @<:@default=yes@:>@])],
	,
	[enable_port_share="yes"]
)

AC_ARG_ENABLE(
	[debug],
	[AS_HELP_STRING([--disable-debug], [disable debugging support (disable gremlin and verb 7+ messages) @<:@default=yes@:>@])],
	,
	[enable_debug="yes"]
)

AC_ARG_ENABLE(
	[small],
	[AS_HELP_STRING([--enable-small], [enable smaller executable size (disable OCC, usage message, and verb 4 parm list) @<:@default=no@:>@])],
	,
	[enable_small="no"]
)

AC_ARG_ENABLE(
	[iproute2],
	[AS_HELP_STRING([--enable-iproute2], [enable support for iproute2 @<:@default=no@:>@])],
	,
	[enable_iproute2="no"]
)

AC_ARG_ENABLE(
	[def-auth],
	[AS_HELP_STRING([--disable-def-auth], [disable deferred authentication @<:@default=yes@:>@])],
	,
	[enable_def_auth="yes"]
)

AC_ARG_ENABLE(
	[pf],
	[AS_HELP_STRING([--disable-pf], [disable internal packet filter @<:@default=yes@:>@])],
	,
	[enable_pf="yes"]
)

AC_ARG_ENABLE(
	[plugin-auth-pam],
	[AS_HELP_STRING([--disable-plugin-auth-pam], [disable auth-pam plugin @<:@default=platform specific@:>@])],
	,
	[
		case "$host" in
			*-*-openbsd*) enable_plugin_auth_pam="no";;
			*-mingw*) enable_plugin_auth_pam="no";;
			*) enable_plugin_auth_pam="yes";;
		esac
	]
)

AC_ARG_ENABLE(
	[plugin-down-root],
	[AS_HELP_STRING([--disable-plugin-down-root], [disable down-root plugin @<:@default=platform specific@:>@])],
	,
	[
		case "$host" in
			*-mingw*) enable_plugin_down_root="no";;
			*) enable_plugin_down_root="yes";;
		esac
	]
)

AC_ARG_ENABLE(
	[pam-dlopen],
	[AS_HELP_STRING([--enable-pam-dlopen], [dlopen libpam @<:@default=no@:>@])],
	,
	[enable_pam_dlopen="no"]
)

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict], [enable strict compiler warnings (debugging option) @<:@default=no@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic], [enable pedantic compiler warnings, will not generate a working executable (debugging option) @<:@default=no@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[strict-options],
	[AS_HELP_STRING([--enable-strict-options], [enable strict options check between peers (debugging option) @<:@default=no@:>@])],
	,
	[enable_strict_options="no"]
)

AC_ARG_ENABLE(
	[selinux],
	[AS_HELP_STRING([--enable-selinux], [enable SELinux support @<:@default=no@:>@])],
	,
	[enable_selinux="no"]
)

AC_ARG_ENABLE(
	[systemd],
	[AS_HELP_STRING([--enable-systemd], [enable systemd suppport @<:@default=no@:>@])],
	,
	[enable_systemd="no"]
)

AC_ARG_WITH(
	[special-build],
	[AS_HELP_STRING([--with-special-build=STRING], [specify special build string])],
	[test -n "${withval}" && AC_DEFINE_UNQUOTED([CONFIGURE_SPECIAL_BUILD], ["${withval}"], [special build string])]
)

AC_ARG_WITH(
	[mem-check],
	[AS_HELP_STRING([--with-mem-check=TYPE], [build with debug memory checking, TYPE=no|dmalloc|valgrind|ssl @<:@default=no@:>@])],
	[
		case "${withval}" in
			dmalloc|valgrind|ssl|no) ;;
			*) AC_MSG_ERROR([bad value ${withval} for --mem-check]) ;;
		esac
	],
	[with_mem_check="no"]
)

AC_ARG_WITH(
	[crypto-library],
	[AS_HELP_STRING([--with-crypto-library=library], [build with the given crypto library, TYPE=openssl|polarssl @<:@default=openssl@:>@])],
	[
		case "${withval}" in 
			openssl|polarssl) ;;
			*) AC_MSG_ERROR([bad value ${withval} for --with-crypto-library]) ;;
		esac
	],
	[with_crypto_library="openssl"]
)

AC_ARG_WITH(
	[plugindir],
	[AS_HELP_STRING([--with-plugindir], [plugin directory @<:@default=LIBDIR/openvpn@:>@])],
	,
	[with_plugindir="\$(libdir)/openvpn/plugins"]
)
AC_ARG_ENABLE(
	[link-mss],
	[AS_HELP_STRING([--enable-link-mss@<:@=<MSS>@:>@], [Enable limiting
                                permitted TCP/UDP link MSS size. Default: not
				limited (MSS will be @<:@default=65507@:>@
				To limit buffering requirements and enable jumbo
				frames, set to >=8972. To enable regular
				ethernet, and no larger packets, set to 1472.
				This option is useful for embedded systems with
				limited RAM.])
]
)
AS_IF([test "x$enable_link_mss" != "x"],
    [AC_DEFINE_UNQUOTED([LINK_MSS], [${enable_link_mss}],
				[Maximum allowed UDP Link Segment Size])]
)

AC_DEFINE_UNQUOTED([TARGET_ALIAS], ["${host}"], [A string representing our host])
case "$host" in
	*-*-linux*)
		AC_DEFINE([TARGET_LINUX], [1], [Are we running on Linux?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["L"], [Target prefix])
		;;
	*-*-solaris*)
		AC_DEFINE([TARGET_SOLARIS], [1], [Are we running on Solaris?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["S"], [Target prefix])
		;;
	*-*-openbsd*)
		AC_DEFINE([TARGET_OPENBSD], [1], [Are we running on OpenBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["O"], [Target prefix])
		;;
	*-*-freebsd*)
		AC_DEFINE([TARGET_FREEBSD], [1], [Are we running on FreeBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["F"], [Target prefix])
		;;
	*-*-netbsd*)
		AC_DEFINE([TARGET_NETBSD], [1], [Are we running NetBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["N"], [Target prefix])
		;;
	*-*-darwin*)
		AC_DEFINE([TARGET_DARWIN], [1], [Are we running on Mac OS X?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["M"], [Target prefix])
		have_tap_header="yes"
		dnl some Mac OS X tendering (we use vararg macros...)
		CPPFLAGS="$CPPFLAGS -no-cpp-precomp"
		;;
	*-mingw*)
		AC_DEFINE([TARGET_WIN32], [1], [Are we running WIN32?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["W"], [Target prefix])
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
		CPPFLAGS="${CPPFLAGS} -DNTDDI_VERSION=NTDDI_WINXP -D_WIN32_WINNT=_WIN32_WINNT_WINXP"
		WIN32=yes
		;;
	*-*-dragonfly*)
		AC_DEFINE([TARGET_DRAGONFLY], [1], [Are we running on DragonFlyBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["D"], [Target prefix])
		;;
	*)
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["X"], [Target prefix])
		have_tap_header="yes"
		;;
esac

PKG_PROG_PKG_CONFIG
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_MAKE_SET
AC_PROG_GREP
AM_PROG_CC_C_O
AC_PATH_PROG([VALGRIND], [valgrind], [echo Failing test because Valgrind is not installed && false])

AC_ARG_VAR([IFCONFIG], [full path to ipconfig utility])
AC_ARG_VAR([ROUTE], [full path to route utility])
AC_ARG_VAR([IPROUTE], [full path to ip utility])
AC_ARG_VAR([NETSTAT], [path to netstat utility]) # tests
AC_ARG_VAR([MAN2HTML], [path to man2html utility])
AC_ARG_VAR([GIT], [path to git utility])
AC_ARG_VAR([SYSTEMD_ASK_PASSWORD], [path to systemd-ask-password utility])
AC_PATH_PROGS([IFCONFIG], [ifconfig],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_PATH_PROGS([ROUTE], [route],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_PATH_PROGS([IPROUTE], [ip],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_PATH_PROGS([SYSTEMD_ASK_PASSWORD], [systemd-ask-password],, [$PATH:/usr/local/bin:/usr/bin:/bin])
AC_CHECK_PROGS([NETSTAT], [netstat], [netstat], [$PATH:/usr/local/sbin:/usr/sbin:/sbin:/etc]) # tests
AC_CHECK_PROGS([MAN2HTML], [man2html])
AC_CHECK_PROGS([GIT], [git]) # optional
AC_DEFINE_UNQUOTED([IFCONFIG_PATH], ["$IFCONFIG"], [Path to ifconfig tool])
AC_DEFINE_UNQUOTED([IPROUTE_PATH], ["$IPROUTE"], [Path to iproute tool])
AC_DEFINE_UNQUOTED([ROUTE_PATH], ["$ROUTE"], [Path to route tool])
AC_DEFINE_UNQUOTED([SYSTEMD_ASK_PASSWORD_PATH], ["$SYSTEMD_ASK_PASSWORD"], [Path to systemd-ask-password tool])

#
# Libtool
#
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIGNAL
AX_CPP_VARARG_MACRO_ISO
AX_CPP_VARARG_MACRO_GCC
AX_TYPE_SOCKLEN_T
AX_EMPTY_ARRAY
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])
AC_CHECK_HEADERS_ONCE([ \
    stdbool.h \
	stdio.h stdarg.h limits.h \
	time.h errno.h fcntl.h io.h direct.h \
	ctype.h sys/types.h sys/socket.h \
	signal.h unistd.h dlfcn.h \
	netinet/in.h netinet/in_systm.h \
	netinet/tcp.h arpa/inet.h netdb.h \
	windows.h winsock2.h ws2tcpip.h \
	versionhelpers.h \
])
AC_CHECK_HEADERS_ONCE([ \
	sys/time.h sys/ioctl.h sys/stat.h \
	sys/mman.h sys/file.h sys/wait.h \
	unistd.h signal.h libgen.h stropts.h \
	syslog.h pwd.h grp.h \
	sys/sockio.h sys/uio.h linux/sockios.h \
	linux/types.h sys/poll.h sys/epoll.h err.h \
])

SOCKET_INCLUDES="
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
"

AC_CHECK_HEADERS(
	[net/if.h netinet/ip.h resolv.h sys/un.h net/if_utun.h sys/kern_control.h],
	,
	,
	[[${SOCKET_INCLUDES}]]
)

AC_CHECK_TYPES(
	[in_addr_t],
	,
	[AC_DEFINE([in_addr_t], [uint32_t], [Workaround missing in_addr_t])],
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct iphdr],
	[AC_DEFINE([HAVE_IPHDR], [1], [struct iphdr needed for IPv6 support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct sock_extended_err],
	[AC_DEFINE([HAVE_SOCK_EXTENDED_ERR], [1], [struct sock_extended_err needed for extended socket error support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct msghdr],
	[AC_DEFINE([HAVE_MSGHDR], [1], [struct msghdr needed for extended socket error support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct cmsghdr],
	[AC_DEFINE([HAVE_CMSGHDR], [1], [struct cmsghdr needed for extended socket error support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct in_pktinfo],
	[AC_DEFINE([HAVE_IN_PKTINFO], [1], [struct in_pktinfo needed for IP_PKTINFO support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct sockaddr_in6],
	,
	[AC_MSG_ERROR([struct sockaddr_in6 not found, needed for ipv6 transport support.])],
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_DECLS(
	[SO_MARK],
	,
	,
	[[${SOCKET_INCLUDES}]]
)

dnl We emulate signals in Windows
AC_CHECK_DECLS(
	[SIGHUP],
	,
	[AC_DEFINE([SIGHUP], [1], [SIGHUP replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)
AC_CHECK_DECLS(
	[SIGINT],
	,
	[AC_DEFINE([SIGINT], [2], [SIGINT replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)
AC_CHECK_DECLS(
	[SIGUSR1],
	,
	[AC_DEFINE([SIGUSR1], [10], [SIGUSR1 replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)
AC_CHECK_DECLS(
	[SIGUSR2],
	,
	[AC_DEFINE([SIGUSR2], [12], [SIGUSR2 replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)
AC_CHECK_DECLS(
	[SIGTERM],
	,
	[AC_DEFINE([SIGTERM], [15], [SIGTERM replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)

AC_FUNC_FORK

AC_CHECK_FUNCS([ \
	daemon chroot getpwnam setuid nice system getpid dup dup2 \
	getpass strerror syslog openlog mlockall getgrnam setgid \
	setgroups stat flock readv writev time gettimeofday \
	ctime memset vsnprintf strdup \
	setsid chdir putenv getpeername unlink \
	chsize ftruncate execve getpeereid umask basename dirname access \
	epoll_create \
])

# Shared Library Detection (Plugins) -------------------------------------------
AX_SEARCH_LIBS(DL, [dlopen], [dl])

# Socket Library Detection -----------------------------------------------------
AX_SEARCH_LIBS(SOCKETS, [inet_ntoa], [nsl])
AX_SEARCH_LIBS(SOCKETS, [socket], [socket])
AX_SEARCH_LIBS(SOCKETS, [gethostbyname], [resolv])

old_LIBS="${LIBS}"
LIBS="${LIBS} ${SOCKETS_LIBS}"
AC_CHECK_FUNCS([sendmsg recvmsg inet_ntop inet_pton])
# Windows use stdcall for winsock so we cannot auto detect these
m4_define(
	[SOCKET_FUNCS],
[socket recv recvfrom send sendto listen dnl
accept connect bind select gethostbyname inet_ntoa]dnl
)
m4_define(
	[SOCKET_OPT_FUNCS],
	[setsockopt getsockopt getsockname poll]dnl
)
if test "${WIN32}" = "yes"; then
	m4_foreach(
		[F],
		m4_split(SOCKET_FUNCS SOCKET_OPT_FUNCS),
			m4_define([UF], [[m4_join([_], [HAVE], m4_toupper(F))]])
			AC_DEFINE([UF], [1], [Win32 builtin])
	)
else
	AC_CHECK_FUNCS(
		SOCKET_FUNCS,
		,
		[AC_MSG_ERROR([Required library function not found])]
	)
	AC_CHECK_FUNCS(SOCKET_OPT_FUNCS)
fi
LIBS="${old_LIBS}"

# Resolver Lib Detection -------------------------------------------------------
AX_SEARCH_LIBS(RESOLVER, __res_init, resolv bind)
AX_SEARCH_LIBS(RESOLVER, res_9_init, resolv bind)
AX_SEARCH_LIBS(RESOLVER, res_init, resolv bind)
PACKAGE_LIBS="${PACKAGE_LIBS} $RESOLVER_LIBS"

AC_ARG_VAR([TAP_CFLAGS], [C compiler flags for tap])
old_CFLAGS="${CFLAGS}"
CFLAGS="${TAP_CFLAGS}"
AC_CHECK_HEADERS(
	[ \
		net/if_tun.h net/tun/if_tun.h \
		linux/if_tun.h \
		tap-windows.h \
	],
	[have_tap_header="yes"]
)
AC_CHECK_DECLS(
	[TUNSETPERSIST],
	[AC_DEFINE([ENABLE_FEATURE_TUN_PERSIST], [1], [We have persist tun capability])],
	,
	[[
		#ifdef HAVE_LINUX_IF_TUN_H
		#include <linux/if_tun.h>
		#endif
	]]
)
CFLAGS="${old_CFLAGS}"
test "${have_tap_header}" = "yes" || AC_MSG_ERROR([no tap header could be found])

# Selinux Detection ------------------------------------------------------------
AX_SEARCH_LIBS(SELINUX, [setcon], [selinux])

# Pluggable Authentication Module Detection ------------------------------------
AC_ARG_VAR([LIBPAM_CFLAGS], [C compiler flags for libpam])
AC_ARG_VAR([LIBPAM_LIBS], [linker flags for libpam])
AX_SEARCH_LIBS(LIBPAM, [pam_start], [pam])

# Memory debug with valgrind Detection -----------------------------------------
AX_CHECK_HEADER(VALGRIND, [valgrind/memcheck.h])

# Memory debug with dmalloc Detection ------------------------------------------
AX_SEARCH_LIBS(DMALLOC, [dmalloc_malloc], [dmalloc])

# get around bug in dmalloc.h which is unaware that strdup is defined as a macro
# Fixes configure issue "WARNING: dmalloc.h: present but cannot be compiled"
# DMALLOC_CFLAGS="-D_HAVE_STRING_ARCH_strndup"
AX_CHECK_HEADER(DMALLOC,[dmalloc.h])

# Memory debug enabled ---------------------------------------------------------
if test "${with_mem_check}" = "valgrind" -o "${enable_unit_tests}" = "all" ; then
    test "$ac_cv_header_valgrind_memcheck_h" = "yes" || AC_MSG_ERROR([valgrind headers not found.])
    AC_MSG_WARN([Valgrind memory checking activated, but does nothing. VALGRIND_MAKE_READABLE is a placibo?])
fi
if test "${with_mem_check}" = "dmalloc" -o "${enable_unit_tests}" = "all" ; then
    test "$ac_cv_search_dmalloc_malloc" != "no" || AC_MSG_ERROR([dmalloc library not found.])
    test "$ac_cv_header_dmalloc_h" = "yes" || AC_MSG_ERROR([dmalloc headers not found.])
fi

if test "${with_mem_check}" = "ssl" -o "${enable_unit_tests}" = "all" ; then
    test "$ac_cv_search_CRYPTO_mem_ctrl" != "no" || AC_MSG_ERROR([Memory Debugging function in $OpenSSL library not found.])
fi

case "${with_mem_check}" in
  valgrind)
    PACKAGE_CFLAGS="$PACKAGE_CFLAGS ${VALGRIND_CFLAGS} -g -fno-inline"
    PACKAGE_LIBS="$PACKAGE_LIBS ${VALGRIND_LIBS} -g -fno-inline"
    AC_DEFINE([USE_VALGRIND], [1], [Use valgrind memory debugging library])
    ;;

  dmalloc)
    PACKAGE_LIBS="$PACKAGE_LIBS $DMALLOC_LIBS"
    PACKAGE_CFLAGS="$PACKAGE_CFLAGS $DMALLOC_CFLAGS"
    AC_DEFINE(DMALLOC, 1, [Use dmalloc memory debugging library])
    ;;

  ssl)
    AC_DEFINE(CRYPTO_MDEBUG, 1, [Use memory debugging function in $OpenSSL])
    AC_MSG_RESULT([NOTE: $OpenSSL library must be compiled with CRYPTO_MDEBUG])
    ;;
esac

# PKCS11 Helper Detection ------------------------------------------------------
PKG_CHECK_MODULES([PKCS11_HELPER], [libpkcs11-helper-1 >= $required_pkcs11_ver_min],, [have_pkcs11_helper="no"])

# P11KIT Library Detection -----------------------------------------------------
PKG_CHECK_MODULES([P11KIT], [p11-kit-1], [proxy_module="`$PKG_CONFIG --variable=proxy_module p11-kit-1`"
    AC_DEFINE_UNQUOTED([DEFAULT_PKCS11_MODULE], "${proxy_module}", [p11-kit proxy])],
    [have_p11kit="no"])

# OpenSSL SSL/Crypto Detection -------------------------------------------------
PKG_CHECK_MODULES([OPENSSL_CRYPTO], [libcrypto >= $required_openssl_ver_min],,        [have_openssl_crypto="no"])
PKG_CHECK_MODULES([OPENSSL_SSL], [libssl >= $required_openssl_ver_min],,              [have_openssl_ssl="no"])
AX_CHECK_HEADER(OPENSSL_CRYPTO, [openssl/evp.h], [[SSLEAY_VERSION_NUMBER >= $required_openssl_ver_min_hex]])

# Memory debug with openssl Detection ------------------------------------------
AX_SEARCH_LIBS(OPENSSL, CRYPTO_mem_ctrl, crypto)

# OpenSSL Crypto Engine Detection-----------------------------------------------
saved_CFLAGS="${CFLAGS}"
saved_LIBS="${LIBS}"
CFLAGS="${OPENSSL_CRYPTO_CFLAGS}"
LIBS="${OPENSSL_CRYPTO_LIBS}"
AC_CHECK_FUNCS([EVP_CIPHER_CTX_set_key_length])
AC_CHECK_FUNCS(
    [ \
        ENGINE_load_builtin_engines \
        ENGINE_register_all_complete \
        ENGINE_cleanup \
    ], AC_DEFINE([HAVE_OPENSSL_ENGINE], [1], [Use crypto library]), [break])
CFLAGS="${saved_CFLAGS}"
LIBS="${saved_LIBS}"

# PolarSSL Detection -----------------------------------------------------------
AC_ARG_VAR([POLARSSL_CFLAGS], [C compiler flags for PolarSSL])
AC_ARG_VAR([POLARSSL_LIBS], [linker flags for PolarSSL])
AX_SEARCH_LIBS(POLARSSL, [ssl_init], [polarssl],,,[${PKCS11_HELPER_LIBS}])
AX_SEARCH_LIBS(POLARSSL, [aes_crypt_cbc], [polarssl],,,[${PKCS11_HELPER_LIBS}])
AX_SEARCH_LIBS(POLARSSL, [x509_serial_gets], [polarssl],,,[${PKCS11_HELPER_LIBS}])

AX_CHECK_HEADER(POLARSSL, polarssl/version.h, [[POLARSSL_VERSION_NUMBER >= $required_polarssl_ver_min_hex && POLARSSL_VERSION_NUMBER < $required_polarssl_ver_max_hex]])
AX_CHECK_HEADER(POLARSSL, polarssl/config.h, [[defined(POLARSSL_PKCS11_C)]])

# LZO Compression Detection ----------------------------------------------------
AC_ARG_VAR([LZO_CFLAGS], [C compiler flags for lzo])
AC_ARG_VAR([LZO_LIBS], [linker flags for lzo])
AX_SEARCH_LIBS(LZO, lzo1x_1_15_compress, [lzo2 lzo])

saved_CFLAGS="${CFLAGS}"
CFLAGS="${LZO_CFLAGS}"
AC_CHECK_HEADERS([lzo/lzo1x.h lzo1x.h lzo/lzoutil.h lzoutil.h] )
CFLAGS="${saved_CFLAGS}"

# Systemd Libraries Detection --------------------------------------------------
PKG_CHECK_MODULES([libsystemd], [systemd libsystemd],,
      [PKG_CHECK_MODULES([libsystemd], [libsystemd-daemon],, [true])])
AX_CHECK_HEADER(libsystemd, [systemd/sd-daemon.h])

# Systemd Libraries Enabled ----------------------------------------------------
if test "$enable_systemd" = "yes" -o "$enable_unit_tests" = "all" ; then
	test "$ac_cv_header_systemd_sd_daemon_h" = "yes" ||
        AC_MSG_ERROR([systemd development headers not found.])
    saved_LIBS="${LIBS}"
    LIBS="${LIBS} ${libsystemd_LIBS}"
    AC_CHECK_FUNCS([sd_booted], [], [AC_MSG_ERROR([systemd library is missing sd_booted()])])
    if test "$enable_systemd" = "yes" ; then
        PACKAGE_LIBS="$PACKAGE_LIBS ${libsystemd_LIBS}"
        AC_DEFINE(ENABLE_SYSTEMD, 1, [Enable systemd integration])
    fi
    LIBS="${saved_LIBS}"
fi

# GIT versioning Detection -----------------------------------------------------
AC_MSG_CHECKING([git checkout])
GIT_CHECKOUT="no"
if test -n "${GIT}" -a -d "${srcdir}/.git"; then
	AC_DEFINE([HAVE_CONFIG_VERSION_H], [1], [extra version available in config-version.h])
	GIT_CHECKOUT="yes"
fi
AC_MSG_RESULT([${GIT_CHECKOUT}])

# OS Path Separator Detection --------------------------------------------------
if test -n "${SP_PLATFORM_WINDOWS}"; then
	AC_DEFINE_UNQUOTED([PATH_SEPARATOR], ['\\\\'], [Path separator]) #"
	AC_DEFINE_UNQUOTED([PATH_SEPARATOR_STR], ["\\\\"], [Path separator]) #"
else
	AC_DEFINE_UNQUOTED([PATH_SEPARATOR], ['/'], [Path separator])
	AC_DEFINE_UNQUOTED([PATH_SEPARATOR_STR], ["/"], [Path separator])
fi

# Options Consistency Checks ---------------------------------------------------
dnl enable --x509-username-field feature if requested
if test "${enable_x509_alt_username}" = "yes"; then
	if test "${with_crypto_library}" = "polarssl" ; then
		AC_MSG_ERROR([$PolarSSL does not support the --x509-username-field feature])
	fi

	AC_DEFINE([ENABLE_X509ALTUSERNAME], [1], [Enable --x509-username-field feature])
fi

# Package build configuration --------------------------------------------------
test "${ac_cv_header_sys_uio_h}" = "yes" && AC_DEFINE([HAVE_IOVEC], [1], [struct iovec needed for IPv6 support])
test "${enable_multi}" = "yes" && AC_DEFINE([ENABLE_CLIENT_SERVER], [1], [Enable client/server capability])
test "${enable_server}" = "no" && AC_DEFINE([ENABLE_CLIENT_ONLY], [1], [Enable client capability only])
test "${enable_management}" = "yes" && AC_DEFINE([ENABLE_MANAGEMENT], [1], [Enable management server capability])
test "${enable_socks}" = "yes" && AC_DEFINE([ENABLE_SOCKS], [1], [Enable Socks proxy support])
test "${enable_http_proxy}" = "yes" && AC_DEFINE([ENABLE_HTTP_PROXY], [1], [Enable HTTP proxy support])
test "${enable_multihome}" = "yes" && AC_DEFINE([ENABLE_MULTIHOME], [1], [Enable multi-homed UDP server capability])
test "${enable_debug}" = "yes" && AC_DEFINE([ENABLE_DEBUG], [1], [Enable debugging support])
test "${enable_small}" = "yes" && AC_DEFINE([ENABLE_SMALL], [1], [Enable smaller executable size])
test "${enable_fragment}" = "yes" && AC_DEFINE([ENABLE_FRAGMENT], [1], [Enable internal fragmentation support])
test "${enable_port_share}" = "yes" && AC_DEFINE([ENABLE_PORT_SHARE], [1], [Enable TCP Server port sharing])
test "${enable_def_auth}" = "yes" && AC_DEFINE([ENABLE_DEF_AUTH], [1], [Enable deferred authentication])
test "${enable_pf}" = "yes" && AC_DEFINE([ENABLE_PF], [1], [Enable internal packet filter])
test "${enable_strict_options}" = "yes" && AC_DEFINE([ENABLE_STRICT_OPTIONS_CHECK], [1], [Enable strict options check between peers])

# Crypto/SSL Library enabled ---------------------------------------------------
if test "${enable_crypto}" = "yes" -o "${enable_unit_tests}" = "all" ; then
    if test "${with_crypto_library}" = "openssl" -o "${enable_unit_tests}" = "all" ; then
        test "$have_openssl_crypto" = "no" &&
                    AC_MSG_ERROR([$OpenSSL Crypto library not found])
        test "$ac_cv_header_openssl_evp_h" = "yes" ||
                    AC_MSG_ERROR([$OpenSSL Crypto header not found])
    fi
    if test "${with_crypto_library}" = "polarssl" -o "${enable_unit_tests}" = "all" ; then
        test "$ac_cv_search_aes_crypt_cbc" != "no" || AC_MSG_ERROR([$PolarSSL Crypto library not found])
        test "$ac_cv_header_polarssl_version_h" = "yes" || AC_MSG_ERROR([$PolarSSL headers not found])
    fi
fi

if test "${enable_ssl}" = "yes" -o "${enable_unit_tests}" = "all"; then
    if test "${with_crypto_library}" = "openssl" -o "${enable_unit_tests}" = "all" ; then
        test "$have_openssl_ssl" = "no" &&
                    AC_MSG_ERROR([$OpenSSL SSL library not found])
    fi
    if test "${with_crypto_library}" = "polarssl" -o "${enable_unit_tests}" = "all" ; then
        test "$ac_cv_search_ssl_init" != "no" ||
                    AC_MSG_ERROR([$PolarSSL SSL library not found])
        test "$ac_cv_search_x509_serial_gets" != "no" || AC_MSG_ERROR([$PolarSSL X509 library not found])
      if test "${enable_unit_tests}" != "all" ; then
        test "$ac_cv_header_polarssl_config_h" = "no" -a "${enable_pkcs11}" = "yes" &&
                    AC_MSG_ERROR([PKCS11 wrapper not enabled in PolarSSL build, did you mean --disable-pkcs11 ?])
        test "$ac_cv_header_polarssl_config_h" = "yes" -a "${enable_pkcs11}" = "no" &&
                    AC_MSG_ERROR([--enable-pkcs11 is required by $PolarSSL configuration])
                    # TODO: Should OpenVPN automatically follow PolarSSL' pkcs11 config?
                    # It seems the pkcs11 choice is the PolarSSL packager's, not OpenVPN packager's
                    # This would be done with:
                    # enable_pkcs11=$ac_cv_header_polarssl_config_h
      else
        AC_MSG_WARN([TODO - The integration test suite should test both pkcs11 and non- versions])
        AC_MSG_WARN([Add POLARSSL_PKCS11_LIBS and POLARPKCS_NOPKCS11_LIBS detections])
        AC_MSG_WARN([Otherwise one of these modes is not covered by the test suite])
      fi
    fi
fi
if test "${enable_ssl}" = "yes" -a "${enable_crypto}" != "yes"; then
	AC_MSG_ERROR([crypto must be enabled for ssl])
fi

case "${with_crypto_library}" in
  openssl)
		CRYPTO_CRYPTO_CFLAGS="${OPENSSL_CRYPTO_CFLAGS}"
		CRYPTO_CRYPTO_LIBS="${OPENSSL_CRYPTO_LIBS}"
		CRYPTO_SSL_CFLAGS="${OPENSSL_SSL_CFLAGS}"
		CRYPTO_SSL_LIBS="${OPENSSL_SSL_LIBS}"
		AC_DEFINE([ENABLE_CRYPTO_OPENSSL], [1], [Use $OpenSSL library for Crypto/SSL ops])
		;;
  polarssl)
		CRYPTO_CRYPTO_CFLAGS="${POLARSSL_CFLAGS}"
		CRYPTO_CRYPTO_LIBS="${POLARSSL_LIBS}"
		AC_DEFINE([ENABLE_CRYPTO_POLARSSL], [1], [Use $PolarSSL library for Crypto/SSL ops])
		;;
esac

if test "${enable_ssl}" = "yes"; then
    OPTIONAL_CRYPTO_CFLAGS="${OPTIONAL_CRYPTO_CFLAGS} ${CRYPTO_SSL_CFLAGS}"
    OPTIONAL_CRYPTO_LIBS="${OPTIONAL_CRYPTO_LIBS} ${CRYPTO_SSL_LIBS}"
    AC_DEFINE([ENABLE_SSL], [1], [Enable ssl library])
fi

if test "${enable_crypto}" = "yes"; then
	test "${enable_crypto_ofb_cfb}" = "yes" && AC_DEFINE([ENABLE_OFB_CFB_MODE], [1], [Enable OFB and CFB cipher modes])
	OPTIONAL_CRYPTO_CFLAGS="${OPTIONAL_CRYPTO_CFLAGS} ${CRYPTO_CRYPTO_CFLAGS}"
	OPTIONAL_CRYPTO_LIBS="${OPTIONAL_CRYPTO_LIBS} ${CRYPTO_CRYPTO_LIBS}"
	AC_DEFINE([ENABLE_CRYPTO], [1], [Enable crypto library])
fi

# Plugin Features enabled ------------------------------------------------------
if test "${enable_plugins}" = "yes"; then
	OPTIONAL_DL_LIBS="${DL_LIBS}"
	AC_DEFINE([ENABLE_PLUGIN], [1], [Enable plug-in support])
else
	enable_plugin_auth_pam="no"
	enable_plugin_down_root="no"
fi

# OS Utilities enabled ---------------------------------------------------------
if test "${enable_iproute2}" = "yes"; then
	test -z "${IPROUTE}" && AC_MSG_ERROR([ip utility is required but missing])
	AC_DEFINE([ENABLE_IPROUTE], [1], [enable iproute2 support])
else
	if test "${WIN32}" != "yes"; then
		test -z "${ROUTE}" && AC_MSG_ERROR([route utility is required but missing])
		test -z "${IFCONFIG}" && AC_MSG_ERROR([ifconfig utility is required but missing])
	fi
fi

# Selinux Features enabled -----------------------------------------------------
if test "${enable_selinux}" = "yes" -o "${enable_unit_tests}" = "all"; then
	test "$ac_cv_search_setcon" != "no" || AC_MSG_ERROR([libselinux required but missing])
    if test "${enable_selinux}" = "yes"; then
        OPTIONAL_SELINUX_LIBS="$SELINUX_LIBS"
        AC_DEFINE([ENABLE_SELINUX], [1], [SELinux support])
    fi
fi

# Compression Consistency Check ------------------------------------------------
if test "${enable_lzo_stub}" = "yes" -o "${enable_unit_tests}" = "all"; then
	test "${enable_lzo}" = "yes" -a "${enable_lzo_stub}" = "yes" && AC_MSG_ERROR([Cannot have both lzo stub and lzo enabled (use --disable-lzo)])
    if test "${enable_lzo_stub}" = "yes"; then
        AC_DEFINE([ENABLE_LZO_STUB], [1], [Enable compression stub capability])
        AC_DEFINE([ENABLE_LZO], [1], [Enable LZO compression library])
    fi
fi

# LZO Compression enabled ------------------------------------------------------
if test "${enable_lzo}" = "yes" -o "${enable_unit_tests}" = "all"; then
	test "$ac_cv_search_lzo1x_1_15_compress" != "no" || AC_MSG_ERROR([lzo enabled but missing])
    test "$ac_cv_header_lzo_lzoutil_h" = "yes" || AC_MSG_ERROR([lzoutil.h is missing])
    test "$ac_cv_header_lzo_lzo1x_h" = "yes" -o "$ac_cv_header_lzo1x_h" = "yes" || AC_MSG_ERROR([LZO headers were not found])
    if test "${enable_lzo}" = "yes"; then
        OPTIONAL_LZO_CFLAGS="${LZO_CFLAGS}"
        OPTIONAL_LZO_LIBS="${LZO_LIBS}"
        AC_DEFINE([ENABLE_LZO], [1], [Enable LZO compression library])
    fi
fi

# PKCS11 Consistency Check -----------------------------------------------------
if test "${enable_ssl}" != "yes" -a "${enable_pkcs11}" = "yes"; then
	AC_MSG_ERROR([PKCS11 can be enabled only if SSL is enabled])
fi
if test "${enable_pkcs11}" = "yes" -o "${enable_unit_tests}" = "all"; then
	test "$have_pkcs11_helper" = "no" && AC_MSG_ERROR([PKCS11 enabled but $PKCS11_HELPER is missing])
	test "$have_p11kit" = "no" && AC_MSG_ERROR([PKCS11 enabled but P11-kit is missing])
fi

# PKCS11 Features enabled ------------------------------------------------------
if test "${enable_pkcs11}" = "yes" -o "${enable_unit_tests}" = "all"; then
    if test "${enable_pkcs11}" = "yes"; then
        APP_CFLAGS="${APP_CFLAGS} ${PKCS11_HELPER_CFLAGS}"
        APP_LIBS="${APP_LIBS} ${PKCS11_HELPER_LIBS}"
        AC_DEFINE([ENABLE_PKCS11], [1], [Enable $PKCS11_HELPER])
    fi
fi

# Build options ----------------------------------------------------------------
if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	PACKAGE_CFLAGS="${PACKAGE_CFLAGS} -pedantic"
	test "${WIN32}" != "yes" && CFLAGS="${CFLAGS} -ansi"
fi

# Compiler warn abilities ------------------------------------------------------
if test "${enable_strict}" = "yes"; then
	ADD_CFLAGS(PACKAGE, [-Wno-unused-function])
	ADD_CFLAGS(PACKAGE, [-Wno-unused-parameter])
	ADD_CFLAGS(PACKAGE, [-Wsign-compare])
	ADD_CFLAGS(PACKAGE, [-Wuninitialized])
	ADD_CFLAGS(PACKAGE, [-Wall])
fi
if test "${enable_werror}" = "yes"; then
	ADD_CFLAGS(PACKAGE, [-Werror])
fi

if test "${WIN32}" = "yes"; then
	test -z "${MAN2HTML}" && AC_MSG_ERROR([man2html is required for win32])
fi

# Set -std=gnu89 unless user already specified a -std=
case "${CFLAGS}" in
  *-std=*) ;;
  *)       PACKAGE_CFLAGS="${PACKAGE_CFLAGS} -std=gnu89" ;;
esac

# Auth Plugin enabled  ---------------------------------------------------------
if test "${enable_plugin_auth_pam}" = "yes" -o "${enable_unit_tests}" = "all" ; then
    if test "${enable_pam_dlopen}" = "yes" -o "${enable_unit_tests}" = "all"; then
        test "$ac_cv_search_pam_start" != no || AC_MSG_ERROR([libpam required but missing])
        AC_MSG_WARN([USE_PAM_DLOPEN defined in package config but not used in source])
    fi
    if test "${enable_pam_dlopen}" = "no" -o "${enable_unit_tests}" = "all" ; then
        test "$ac_cv_search_dlopen" != "no" || AC_MSG_ERROR([dynamic linker library required but missing])
    fi
fi
if test "${enable_plugin_auth_pam}" = "yes"; then
    PLUGIN_AUTH_PAM_CFLAGS="${LIBPAM_CFLAGS}"
    if test "${enable_pam_dlopen}" = "yes"; then
        AC_DEFINE([USE_PAM_DLOPEN], [1], [dlopen libpam])
        PLUGIN_AUTH_PAM_LIBS="${DL_LIBS}"
    else
        PLUGIN_AUTH_PAM_LIBS="${LIBPAM_LIBS}"
    fi
fi

CONFIGURE_DEFINES="`set | grep '^enable_.*=' ; set | grep '^with_.*='`"
AC_DEFINE_UNQUOTED([CONFIGURE_DEFINES], ["`echo ${CONFIGURE_DEFINES}`"], [Configuration settings])

TAP_WIN_COMPONENT_ID="PRODUCT_TAP_WIN_COMPONENT_ID"
TAP_WIN_MIN_MAJOR="PRODUCT_TAP_WIN_MIN_MAJOR"
TAP_WIN_MIN_MINOR="PRODUCT_TAP_WIN_MIN_MINOR"
AC_DEFINE_UNQUOTED([TAP_WIN_COMPONENT_ID], ["${TAP_WIN_COMPONENT_ID}"], [The tap-windows id])
AC_DEFINE_UNQUOTED([TAP_WIN_MIN_MAJOR], [${TAP_WIN_MIN_MAJOR}], [The tap-windows version number is required for OpenVPN])
AC_DEFINE_UNQUOTED([TAP_WIN_MIN_MINOR], [${TAP_WIN_MIN_MINOR}], [The tap-windows version number is required for OpenVPN])
AC_SUBST([TAP_WIN_COMPONENT_ID])
AC_SUBST([TAP_WIN_MIN_MAJOR])
AC_SUBST([TAP_WIN_MIN_MINOR])

AC_SUBST([OPTIONAL_DL_LIBS])
AC_SUBST([OPTIONAL_SELINUX_LIBS])
AC_SUBST([OPTIONAL_CRYPTO_CFLAGS])
AC_SUBST([OPTIONAL_CRYPTO_LIBS])
AC_SUBST([OPTIONAL_LZO_CFLAGS])
AC_SUBST([OPTIONAL_LZO_LIBS])
AC_SUBST([OPTIONAL_SYSTEMD_LIBS])
AC_SUBST([OPTIONAL_PKCS11_HELPER_CFLAGS])
AC_SUBST([OPTIONAL_PKCS11_HELPER_LIBS])

AC_SUBST([PACKAGE_LIBS])
AC_SUBST([PACKAGE_CFLAGS])
AC_SUBST([APP_CFLAGS])
AC_SUBST([APP_LIBS])
AC_SUBST([PLUGIN_CFLAGS])
AC_SUBST([PLUGIN_LIBS])

AC_SUBST([PLUGIN_AUTH_PAM_CFLAGS])
AC_SUBST([PLUGIN_AUTH_PAM_LIBS])

AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([GIT_CHECKOUT], [test "${GIT_CHECKOUT}" = "yes"])
AM_CONDITIONAL([ENABLE_PLUGIN_AUTH_PAM], [test "${enable_plugin_auth_pam}" = "yes"])
AM_CONDITIONAL([ENABLE_PLUGIN_DOWN_ROOT], [test "${enable_plugin_down_root}" = "yes"])
AM_CONDITIONAL([ENABLE_CRYPTO], [test "${enable_crypto}" = "yes"])

plugindir="${with_plugindir}"
sampledir="\$(docdir)/sample"
AC_SUBST([plugindir])
AC_SUBST([sampledir])

# Output/generated files -------------------------------------------------------
AC_CONFIG_FILES([
	version.sh
	Makefile
	build/Makefile
	build/msvc/Makefile
	build/msvc/msvc-generate/Makefile
	distro/Makefile
	distro/rpm/Makefile
	distro/rpm/openvpn.spec
	include/Makefile
	src/Makefile
	src/compat/Makefile
	src/openvpn/Makefile
	src/openvpnserv/Makefile
	src/plugins/Makefile
	src/plugins/auth-pam/Makefile
	src/plugins/down-root/Makefile
	sample/Makefile
	doc/Makefile
    tests/Makefile
])
AC_CONFIG_FILES([tests/t_client.sh], [chmod +x tests/t_client.sh])

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

AM_CONDITIONAL([IMPLEMENTED_rfc4821], [true])

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

AM_CONDITIONAL([IMPLEMENTED_mtu_2_0], [false])
AM_CONDITIONAL([IMPLEMENTED_mtu_2_4],
    [test -f $(dirname "$srcdir/$ac_unique_file")/mtu.c &&
    ${GREP} '^frame_init_mssfix' $(dirname "$srcdir/$ac_unique_file")/mtu.c >/dev/null])
AM_CONDITIONAL([IMPLEMENTED_mtu2], [true])

AM_CONDITIONAL([IMPLEMENTED_sitnl_2_5], [test -f $(dirname "$srcdir/$ac_unique_file")/networking_sitnl.c])

# #################### End Feature Implementations ############################

# ######################## Buildable Packages #################################
AM_CONDITIONAL([INTEGRATED_openvpn], [expr "$PACKAGE_STRING" : 'OpenVPN ' >/dev/null])
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
