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
AUTOMAKE_OPTIONS = color-tests parallel-tests nostdinc

include $(top_srcdir)/tests/srcpaths.inc
include $(top_srcdir)/tests/integration/rules.inc

P2P_LOG_COMPILER = $(srcdir)/test-it-starts.sh
AM_P2P_LOG_FLAGS = -V "$(PACKAGE_STRING)" -C "--version"

COMBO_LOG_COMPILER = $(srcdir)/test-it-starts.sh
AM_COMBO_LOG_FLAGS = -V "$(PACKAGE_STRING)" -C "--version"

SERVER_LOG_COMPILER = $(srcdir)/test-it-starts.sh
AM_SERVER_LOG_FLAGS = -V "$(PACKAGE_STRING)" -C "--version"

CLIENT_LOG_COMPILER = $(srcdir)/test-it-starts.sh
AM_CLIENT_LOG_FLAGS = -V "$(PACKAGE_STRING)" -C "--version"

# Sources common to all releases of the project, and all buildables
# (client/server/combo/util)
common_sources = \
    $(openvpn_srcdir)/base64.c              $(openvpn_srcdir)/base64.h \
    $(openvpn_srcdir)/buffer.c              $(openvpn_srcdir)/buffer.h \
    $(openvpn_srcdir)/crypto.c              $(openvpn_srcdir)/crypto.h \
    $(openvpn_srcdir)/error.c               $(openvpn_srcdir)/error.h \
    $(openvpn_srcdir)/event.c               $(openvpn_srcdir)/event.h \
    $(openvpn_srcdir)/fdmisc.c              $(openvpn_srcdir)/fdmisc.h \
    $(openvpn_srcdir)/forward.c             $(openvpn_srcdir)/forward.h \
                                            $(openvpn_srcdir)/forward-inline.h \
    $(openvpn_srcdir)/fragment.c            $(openvpn_srcdir)/fragment.h \
    $(openvpn_srcdir)/gremlin.c             $(openvpn_srcdir)/gremlin.h \
    $(openvpn_srcdir)/helper.c              $(openvpn_srcdir)/helper.h \
    $(openvpn_srcdir)/init.c                $(openvpn_srcdir)/init.h \
    $(openvpn_srcdir)/interval.c            $(openvpn_srcdir)/interval.h \
    $(openvpn_srcdir)/list.c                $(openvpn_srcdir)/list.h \
    $(openvpn_srcdir)/lzo.c                 $(openvpn_srcdir)/lzo.h \
    $(openvpn_srcdir)/manage.c              $(openvpn_srcdir)/manage.h \
    $(openvpn_srcdir)/mbuf.c                $(openvpn_srcdir)/mbuf.h \
    $(openvpn_srcdir)/misc.c                $(openvpn_srcdir)/misc.h \
    $(openvpn_srcdir)/mroute.c              $(openvpn_srcdir)/mroute.h \
    $(openvpn_srcdir)/mss.c                 $(openvpn_srcdir)/mss.h \
    $(openvpn_srcdir)/mtcp.c                $(openvpn_srcdir)/mtcp.h \
    $(openvpn_srcdir)/mtu.c                 $(openvpn_srcdir)/mtu.h \
    $(openvpn_srcdir)/mudp.c                $(openvpn_srcdir)/mudp.h \
    $(openvpn_srcdir)/multi.c               $(openvpn_srcdir)/multi.h \
    $(openvpn_srcdir)/ntlm.c                $(openvpn_srcdir)/ntlm.h \
    $(openvpn_srcdir)/occ.c                 $(openvpn_srcdir)/occ.h \
                                            $(openvpn_srcdir)/occ-inline.h \
    $(openvpn_srcdir)/openvpn.c             $(openvpn_srcdir)/openvpn.h \
    $(openvpn_srcdir)/options.c             $(openvpn_srcdir)/options.h \
    $(openvpn_srcdir)/otime.c               $(openvpn_srcdir)/otime.h \
    $(openvpn_srcdir)/packet_id.c           $(openvpn_srcdir)/packet_id.h \
    $(openvpn_srcdir)/perf.c                $(openvpn_srcdir)/perf.h \
    $(openvpn_srcdir)/ping.c                $(openvpn_srcdir)/ping.h \
                                            $(openvpn_srcdir)/ping-inline.h \
    $(openvpn_srcdir)/plugin.c              $(openvpn_srcdir)/plugin.h \
    $(openvpn_srcdir)/pool.c                $(openvpn_srcdir)/pool.h \
    $(openvpn_srcdir)/proto.c               $(openvpn_srcdir)/proto.h \
    $(openvpn_srcdir)/proxy.c               $(openvpn_srcdir)/proxy.h \
    $(openvpn_srcdir)/push.c                $(openvpn_srcdir)/push.h \
    $(openvpn_srcdir)/reliable.c            $(openvpn_srcdir)/reliable.h \
    $(openvpn_srcdir)/route.c               $(openvpn_srcdir)/route.h \
    $(openvpn_srcdir)/schedule.c            $(openvpn_srcdir)/schedule.h \
    $(openvpn_srcdir)/session_id.c          $(openvpn_srcdir)/session_id.h \
    $(openvpn_srcdir)/shaper.c              $(openvpn_srcdir)/shaper.h \
    $(openvpn_srcdir)/sig.c                 $(openvpn_srcdir)/sig.h \
    $(openvpn_srcdir)/socket.c              $(openvpn_srcdir)/socket.h \
    $(openvpn_srcdir)/socks.c               $(openvpn_srcdir)/socks.h \
    $(openvpn_srcdir)/ssl.c                 $(openvpn_srcdir)/ssl.h \
    $(openvpn_srcdir)/status.c              $(openvpn_srcdir)/status.h \
    $(openvpn_srcdir)/tun.c                 $(openvpn_srcdir)/tun.h \
    $(openvpn_srcdir)/basic.h \
    $(openvpn_srcdir)/circ_list.h \
    $(openvpn_srcdir)/common.h \
    $(openvpn_srcdir)/errlevel.h \
    $(openvpn_srcdir)/integer.h \
    $(openvpn_srcdir)/memdbg.h \
    $(openvpn_srcdir)/openvpn-plugin.h \
    $(openvpn_srcdir)/syshead.h
    
# If any test is expected to fail (eg, new test, WIP, on TODO list), add it here
# XFAIL_TESTS +=

# TODO: Add @SYSTEMD_LIBS@ test, added @ 027dd7f v2.3.5
# TODO: Add @RESOLVER_LIBS@ test, added @ ae9aff25 2.3.7

# Build options/mutators which I have noticed in config.h, but have not yet
# written a test to exercise. Maybe you can add some. Most such options
# will cause test failures when exercised on their own, without other options
# being enabled, but some fail when specific combinations are enabled.
# Also, not all of these may exist in all releases. I picked them out of the
# 2.3 release, but some may need to be moved further below, under a conditional
# All these options are DISABLED in all current tests, they need to be
# INDIVIDUALLY AND SPECIFICALLY ENABLED in order to test them.
#
# Others are HARDCODED in syshead.h; those have not been included here, since
# they can't be turned off for an off/on test

UNTESTED_mutators_TODO = \
    ENABLE_DEF_AUTH \
    ENABLE_FEATURE_TUN_PERSIST \
    ENABLE_IPROUTE \
    ENABLE_LZO_STUB \
    ENABLE_COMP_STUB \
    ENABLE_MULTIHOME \
    ENABLE_OFB_CFB_MODE \
    ENABLE_PF \
    ENABLE_PKCS11 \
    ENABLE_PORT_SHARE \
    ENABLE_X509ALTUSERNAME \
    ENABLE_STRICT_OPTIONS_CHECK \
    CRYPTO_MDEBUG \
    DEFAULT_PKCS11_MODULE \
    DMALLOC


mutators = $(uNTESTED_mutators_TODO) \
    NDEBUG \
    ENABLE_DEBUG \
    ENABLE_SMALL \
    ENABLE_CLIENT_SERVER \
    ENABLE_CLIENT_ONLY \
    ENABLE_MANAGEMENT \
    ENABLE_HTTP_PROXY \
    ENABLE_FRAGMENT \
    ENABLE_PASSWORD_SAVE \
    ENABLE_SOCKS

# A full complement of features. This is not very useful to answer the 
# does-it-build question because it is equivalent to all #ifdefs being removed
# Builds are more likely to fail when some feature is turned off, but others
# depend on it.
mutate_full =   -DENABLE_FRAGMENT \
				-DENABLE_MANAGEMENT \
				-DENABLE_PASSWORD_SAVE \
				-DENABLE_HTTP_PROXY \
				-DENABLE_SOCKS

mutate_full_CFLAGS =
mutate_full_LIBS   =

# Handle USE_ reorg at 2.3 where mutators were renamed from USE_{LZO,CRYPTO,SSL}
# to ENABLE_{LZO,CRYPTO_SSL}
if !INTEGRATED_openvpn_2_0
# Mutators added after 2.0 but before last 2.1 revision

# In 2.3 at 9b33b5a4b, USE_SSL and USE_CRYPTO were renamed ENABLE_*
mutators +=                 ENABLE_CRYPTO_OPENSSL

# In 2.3 at 74bbc71b7, USE_LZO was renamed to ENABLE_LZO

# TODO: Add test for ENABLE_PUSH_PEER_INFO mutator added at 4f79d3ec (2.1.1 and 2.2)
# Hardcoded in syshead.h
# mutators +=           ENABLE_PUSH_PEER_INFO

base_LDADD         =
if !INTEGRATED_openvpn_2_1
# Mutators added after 2.1 but before last 2.2 revision
if !INTEGRATED_openvpn_2_2
# Mutators added after 2.2 but before last 2.3 revision

# In 2.3 at bdae411, USE_LIBDL was replaced with ENABLE_PLUGIN
mutators +=                 ENABLE_PLUGIN
mutate_ENABLE_PLUGIN =      -DENABLE_PLUGIN -I$(openvpn_includedir)

mutators +=                 ENABLE_LZO \
							ENABLE_SELINUX \
							ENABLE_SYSTEMD
mutate_ENABLE_LZO =         -DENABLE_LZO

mutators +=                 ENABLE_CRYPTO

mutate_full        += -DENABLE_SELINUX -DENABLE_SYSTEMD
mutate_full_CFLAGS += @libsystemd_CFLAGS@
mutate_full_LIBS   += @SELINUX_LIBS@ @libsystemd_LIBS@

if !INTEGRATED_openvpn_2_3
# Mutators added after 2.3 but before last 2.4 revision

mutators +=                 ENABLE_LZ4
mutate_ENABLE_LZ4 =         -DENABLE_LZ4 @LZ4_CFLAGS@

mutate_CRYPTO_LIBS_1 =      @OPENSSL_LIBS@

mutate_ENABLE_CRYPTO_1 =    -DENABLE_CRYPTO -DENABLE_CRYPTO_OPENSSL @OPENSSL_CFLAGS@
mutate_ENABLE_CRYPTO_2 =    -DENABLE_CRYPTO -DENABLE_CRYPTO_MBEDTLS @MBEDTLS_CFLAGS@
mutate_CRYPTO_LIBS_2 =      @MBEDTLS_LIBS@

mutate_ENABLE_COMP_STUB =   -DENABLE_COMP_STUB

mutate_full += -DENABLE_LZ4
mutate_full_CFLAGS += @LZ4_CFLAGS@
mutate_full_LIBS += @LZ4_LIBS@

if !INTEGRATED_openvpn_2_4
# Mutators added after 2.4 but before last 2.5 revision

else
# 2.4-only mutators
endif
else
# 2.3-only mutators

mutators +=                 ENABLE_SSL ENABLE_CRYPTO_POLARSSL
mutate_ENABLE_SSL =         -DENABLE_SSL

mutate_SSL_LIBS_1 =         @OPENSSL_SSL_LIBS@
mutate_CRYPTO_LIBS_1 =      @OPENSSL_CRYPTO_LIBS@

mutate_ENABLE_CRYPTO_1 =    -DENABLE_CRYPTO -DENABLE_CRYPTO_OPENSSL @OPENSSL_CRYPTO_CFLAGS@
mutate_ENABLE_CRYPTO_2 =    -DENABLE_CRYPTO -DENABLE_CRYPTO_POLARSSL @POLARSSL_CFLAGS@
mutate_CRYPTO_LIBS_2 =      @POLARSSL_LIBS@
mutate_SSL_LIBS_2 =         @POLARSSL_LIBS@

mutate_ENABLE_COMP_STUB =   -DENABLE_LZO_STUB


endif
else
# 2.2-only mutators
mutators +=                 USE_LIBDL
mutate_ENABLE_PLUGIN =      -DUSE_LIBDL

mutators +=                 USE_LZO
mutate_ENABLE_LZO =         -DUSE_LZO

mutators +=                 USE_CRYPTO USE_SSL
mutate_ENABLE_CRYPTO_1 =    -DUSE_CRYPTO @CRYPTO_CFLAGS@
mutate_ENABLE_SSL =         -DUSE_SSL

mutate_CRYPTO_LIBS_1 =      @CRYPTO_LIBS@
mutate_SSL_LIBS_1 =         @SSL_LIBS@

endif
else
# 2.1-only mutators
mutators +=                 USE_LIBDL
mutate_ENABLE_PLUGIN =      -DUSE_LIBDL

mutators +=                 USE_CRYPTO USE_SSL
mutate_ENABLE_CRYPTO_1 =    -DUSE_CRYPTO @CRYPTO_CFLAGS@
mutate_ENABLE_SSL =         -DUSE_SSL

mutators +=                 USE_LZO
mutate_ENABLE_LZO =         -DUSE_LZO

mutate_CRYPTO_LIBS_1 =      @CRYPTO_LIBS@
mutate_SSL_LIBS_1 =         @SSL_LIBS@

endif
else
# 2.0-only mutators
mutators +=                 USE_LIBDL
mutate_ENABLE_PLUGIN =      -DUSE_LIBDL

mutators +=                 USE_CRYPTO USE_SSL
mutate_ENABLE_CRYPTO_1 =    -DUSE_CRYPTO @CRYPTO_CFLAGS@
mutate_ENABLE_SSL =         -DUSE_SSL

mutators +=                 USE_LZO
mutate_ENABLE_LZO =         -DUSE_LZO

mutate_CRYPTO_LIBS_1 =      @CRYPTO_LIBS@
mutate_SSL_LIBS_1 =         @SSL_LIBS@

endif

if !INTEGRATED_openvpn_2_0
if !INTEGRATED_openvpn_2_1
if !INTEGRATED_openvpn_2_2
if !INTEGRATED_openvpn_2_3
if !INTEGRATED_ovpn_1_0
mutate_ENABLE_PLUGIN += -DPLUGIN_LIBDIR=\"${plugindir}\"
endif
endif
endif
endif
endif

mutate_full        += $(mutate_ENABLE_LZO) $(mutate_ENABLE_PLUGIN)
mutate_full_CFLAGS += @LZO_CFLAGS@
mutate_full_LIBS   += @LZO_LIBS@ @DL_LIBS@

# Sources variations for each version
if !INTEGRATED_openvpn_2_0
# Sources added after 2.0 but before last 2.1 revision
common_sources += \
    $(openvpn_srcdir)/clinat.c              $(openvpn_srcdir)/clinat.h \
    $(openvpn_srcdir)/dhcp.c                $(openvpn_srcdir)/dhcp.h \
    $(openvpn_srcdir)/lladdr.c              $(openvpn_srcdir)/lladdr.h \
    $(openvpn_srcdir)/pf.c                  $(openvpn_srcdir)/pf.h \
    $(openvpn_srcdir)/ps.c                  $(openvpn_srcdir)/ps.h \
    $(openvpn_srcdir)/win32.c               $(openvpn_srcdir)/win32.h

if !INTEGRATED_openvpn_2_1
# Sources added after 2.1 but before last 2.2 revision
common_sources += \
    $(openvpn_srcdir)/httpdigest.c          $(openvpn_srcdir)/httpdigest.h
if !INTEGRATED_openvpn_2_2
# Sources added after 2.2 but before last 2.3 revision
common_sources += \
    $(openvpn_srcdir)/platform.c            $(openvpn_srcdir)/platform.h \
    $(openvpn_srcdir)/console.c             $(openvpn_srcdir)/console.h \
    $(openvpn_srcdir)/crypto_openssl.c      $(openvpn_srcdir)/crypto_openssl.h \
    $(openvpn_srcdir)/crypto_backend.h \
    $(openvpn_srcdir)/mstats.c              $(openvpn_srcdir)/mstats.h \
    $(openvpn_srcdir)/ssl_openssl.c         $(openvpn_srcdir)/ssl_openssl.h \
    $(openvpn_srcdir)/ssl_verify.c          $(openvpn_srcdir)/ssl_verify.h \
    $(openvpn_srcdir)/ssl_verify_openssl.c  $(openvpn_srcdir)/ssl_verify_openssl.h
if UNIT_TESTED_rfc4821
common_sources += \
    $(openvpn_srcdir)/rfc4821.c             $(openvpn_srcdir)/rfc4821.h
endif
if INTEGRATED_ovpn_1_0
# Sources added after 2.2 but before last ovpn/1.0 revision
common_sources += \
    $(openvpn_srcdir)/netlink.c             $(openvpn_srcdir)/netlink.h \
    $(openvpn_srcdir)/balancer.c            $(openvpn_srcdir)/balancer.h
endif
if !INTEGRATED_openvpn_2_3
# Sources added after 2.3 but before last 2.4 revision
common_sources += \
    $(openvpn_srcdir)/argv.c                $(openvpn_srcdir)/arg.h \
    $(openvpn_srcdir)/comp.c                $(openvpn_srcdir)/comp.h \
    $(openvpn_srcdir)/comp-lz4.c            $(openvpn_srcdir)/comp-lz4.h \
    $(openvpn_srcdir)/compstub.c \
    $(openvpn_srcdir)/console_builtin.c \
    $(openvpn_srcdir)/console_systemd.c \
    $(openvpn_srcdir)/crypto_mbedtls.c      $(openvpn_srcdir)/crypto_mbedtls.h \
    $(openvpn_srcdir)/openssl-compat.h \
    $(openvpn_srcdir)/ssl_mbedtls.c         $(openvpn_srcdir)/ssl_mbedtls.h \
    $(openvpn_srcdir)/ssl_verify_mbedtls.c  $(openvpn_srcdir)/ssl_verify_mbedtls.h \
    $(openvpn_srcdir)/tls_crypt.c           $(openvpn_srcdir)/tls_crypt.h
if !INTEGRATED_openvpn_2_4
# Sources added after 2.4 but before last 2.5 revision
if !INTEGRATED_openvpn_2_5
# Sources added after 2.5 but before last 2.6 revision
# Add new versions here
# if !INTEGRATED_openvpn_future_version
# common_source += ...
# else
# endif
else
# 2.5-only sources
endif
else
# 2.4-only sources
endif
else
# 2.3-only sources
common_sources += \
    $(openvpn_srcdir)/ssl_polarssl.c        $(openvpn_srcdir)/ssl_polarssl.h \
    $(openvpn_srcdir)/crypto_polarssl.c     $(openvpn_srcdir)/crypto_polarssl.h \
    $(openvpn_srcdir)/ssl_verify_polarssl.c $(openvpn_srcdir)/ssl_verify_polarssl.h

# note win32_wfp.h was added with 367067f at 2.3.8
common_sources += \
    $(openvpn_srcdir)/win32_wfp.h

endif
else
# 2.2-sources
endif
else
# 2.1-only sources
common_sources += \
    $(openvpn_srcdir)/thread.c              $(openvpn_srcdir)/thread.h
endif
else
# 2.0-only sources
common_sources += \
    $(openvpn_srcdir)/thread.c              $(openvpn_srcdir)/thread.h
base_LDADD         =                        @WIN32_LIBS@
endif


combo_sources =  $(common_sources)
server_sources = $(common_sources)
client_sources = $(common_sources)
util_sources =   $(common_sources)

# Integration tests to be run by developers/maintainers, --enable-unit-tests=all
all_tests =

# FIXME: Fix compile warnings and enable strict integration test w/-Wall -Werror
# Most warnings are caused by #ifdef bugs, ie, dangling, unused code that
# belongs inside an #ifdef but it is outside.
base_CFLAGS        =                        $(TEST_CFLAGS) -Wall
base_CPPFLAGS      =                        -I$(openvpn_srcdir) \
                                            -I$(compat_srcdir)

if ENABLE_UNITTESTS_ALL

all_tests += multi.plain.combo
multi_plain_combo_CFLAGS    =               $(base_CFLAGS)
multi_plain_combo_LDADD     =               $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1)
multi_plain_combo_SOURCES   =               $(combo_sources)
multi_plain_combo_CPPFLAGS  =               -DENABLE_CLIENT_SERVER \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
                                            -I. $(base_CPPFLAGS)

all_tests += multi.plugin.combo
multi_plugin_combo_CFLAGS =                 $(base_CFLAGS)
multi_plugin_combo_LDADD =                  $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
                                            @DL_LIBS@
multi_plugin_combo_SOURCES   =              $(combo_sources)
multi_plugin_combo_CPPFLAGS  =             -DENABLE_CLIENT_SERVER \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
                                            $(mutate_ENABLE_PLUGIN) \
                                            -I. $(base_CPPFLAGS)

all_tests += multi.management.combo
multi_management_combo_CFLAGS    =          $(base_CFLAGS)
multi_management_combo_LDADD     =          $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1)
multi_management_combo_SOURCES   =          $(combo_sources)
multi_management_combo_CPPFLAGS  =          -DENABLE_CLIENT_SERVER \
											-DENABLE_MANAGEMENT \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
                                            -I. $(base_CPPFLAGS)

all_tests += multiclient.client
multiclient_client_CFLAGS    =              $(base_CFLAGS)
multiclient_client_LDADD     =              $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1)
multiclient_client_SOURCES   =              $(client_sources)
multiclient_client_CPPFLAGS  =              -DENABLE_CLIENT_SERVER \
                                            -DENABLE_CLIENT_ONLY \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
                                            -I. $(base_CPPFLAGS)

all_tests += easy.p2p
easy_p2p_CFLAGS    =                        $(base_CFLAGS)
easy_p2p_LDADD     =                        $(base_LDADD)
easy_p2p_SOURCES   =                        $(client_sources)
easy_p2p_CPPFLAGS  =                        -I. $(base_CPPFLAGS)

all_tests += easy.plugin.p2p
easy_plugin_p2p_CFLAGS    =                 $(base_CFLAGS)
easy_plugin_p2p_LDADD     =                 $(base_LDADD) \
                                            @DL_LIBS@
easy_plugin_p2p_SOURCES   =                 $(client_sources)
easy_plugin_p2p_CPPFLAGS  =                 $(mutate_ENABLE_PLUGIN) \
                                            -I. $(base_CPPFLAGS)

all_tests += easy.management.p2p
easy_management_p2p_CFLAGS    =             $(base_CFLAGS)
easy_management_p2p_LDADD     =             $(base_LDADD)
easy_management_p2p_SOURCES   =             $(client_sources)
easy_management_p2p_CPPFLAGS  =             -DENABLE_MANAGEMENT \
                                            -I. $(base_CPPFLAGS)

all_tests += easy.lzo.p2p
easy_lzo_p2p_CFLAGS    =                    $(base_CFLAGS)
easy_lzo_p2p_LDADD     =                    $(base_LDADD) \
                                            @LZO_LIBS@
easy_lzo_p2p_SOURCES   =                    $(client_sources)
easy_lzo_p2p_CPPFLAGS  =                    -DENABLE_LZO \
                                            -I. $(base_CPPFLAGS)

if !INTEGRATED_openvpn_2_0
if !INTEGRATED_openvpn_2_1
if !INTEGRATED_openvpn_2_2
all_tests += easy.lzo-compstub.p2p
easy_lzo_compstub_p2p_CFLAGS    =           $(base_CFLAGS)
easy_lzo_compstub_p2p_LDADD     =           $(base_LDADD) \
                                            @LZO_LIBS@
easy_lzo_compstub_p2p_SOURCES   =           $(client_sources)
easy_lzo_compstub_p2p_CPPFLAGS  =           -DENABLE_LZO \
											$(mutate_ENABLE_COMP_STUB) \
                                            -I. $(base_CPPFLAGS)
endif
endif
endif

all_tests += multi.lzo.combo
multi_lzo_combo_CFLAGS =                    $(base_CFLAGS)
multi_lzo_combo_LDADD =                     $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
                                            @LZO_LIBS@
multi_lzo_combo_SOURCES   =                 $(server_sources)
multi_lzo_combo_CPPFLAGS  =                 -DENABLE_CLIENT_SERVER \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
                                            $(mutate_ENABLE_LZO) \
                                            -I. $(base_CPPFLAGS)

if !INTEGRATED_openvpn_2_0
if !INTEGRATED_openvpn_2_1
if !INTEGRATED_openvpn_2_2
all_tests += multi.lzo-compstub.combo
multi_lzo_compstub_combo_CFLAGS =           $(base_CFLAGS)
multi_lzo_compstub_combo_LDADD =            $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
                                            @LZO_LIBS@
multi_lzo_compstub_combo_SOURCES =          $(server_sources)
multi_lzo_compstub_combo_CPPFLAGS =         -DENABLE_CLIENT_SERVER \
											$(mutate_ENABLE_CRYPTO_1) \
											$(mutate_ENABLE_SSL) \
											$(mutate_ENABLE_LZO) \
											$(mutate_ENABLE_COMP_STUB) \
											-I. $(base_CPPFLAGS)
endif
endif
endif

all_tests += multiclient.lzo-plugin.client
multiclient_lzo_plugin_client_CFLAGS =      $(base_CFLAGS)
multiclient_lzo_plugin_client_LDADD =       $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
                                            @DL_LIBS@ \
                                            @LZO_LIBS@
multiclient_lzo_plugin_client_SOURCES =     $(server_sources)
multiclient_lzo_plugin_client_CPPFLAGS=     -DENABLE_CLIENT_SERVER \
                                            -DENABLE_CLIENT_ONLY \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
                                            $(mutate_ENABLE_LZO) \
                                            $(mutate_ENABLE_PLUGIN) \
                                            -I. $(base_CPPFLAGS)

# Plugins enabled, but not multi. @LD_LIBS@ must not be required to build
all_tests += easy.full.ndebug.p2p
easy_full_ndebug_p2p_CFLAGS    =            $(base_CFLAGS) $(mutate_full_CFLAGS)
easy_full_ndebug_p2p_LDADD     =            $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
											$(mutate_full_LIBS)
easy_full_ndebug_p2p_SOURCES   =            $(combo_sources)
easy_full_ndebug_p2p_CPPFLAGS  =            -DNDEBUG \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
											$(mutate_full) \
                                            -I. $(base_CPPFLAGS)

# The ndebug build is very similar to the plain build in many versions of the
# project. But there are (or will be) some versions where the ASSERT macro calls
# the standard glibc assert() instead of the openvpn assert_failed() function.
# These versions will be broken if built with -DNDEBUG and where the the
# ASSERT() expression modifies program state. To remove the ndebug test
# in the test branch would leave other source branches vulnerable/blind
# to bugs like ASSERT() that modify state.
# TDLR: Do not remove the _ndebug_ tests.
# Kitchen sink. Everything is enabled. Combo
all_tests += multi.full.ndebug.combo
multi_full_ndebug_combo_CFLAGS    =         $(base_CFLAGS) $(mutate_full_CFLAGS)
multi_full_ndebug_combo_LDADD     =         $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
											$(mutate_full_LIBS)
multi_full_ndebug_combo_SOURCES   =         $(combo_sources)
multi_full_ndebug_combo_CPPFLAGS  =         -DNDEBUG \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
											-DENABLE_CLIENT_SERVER \
											$(mutate_full) \
                                            -I. $(base_CPPFLAGS)

# Kitchen sink. Everything is enabled. Combo, Small build
# Closest to a swiss army knife, production build (no debug code)
all_tests += multi.full.ndebug.small.combo
multi_full_ndebug_small_combo_CFLAGS    =   $(base_CFLAGS) $(mutate_full_CFLAGS)
multi_full_ndebug_small_combo_LDADD     =   $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
											$(mutate_full_LIBS)
multi_full_ndebug_small_combo_SOURCES   =   $(combo_sources)
multi_full_ndebug_small_combo_CPPFLAGS  =   -DNDEBUG \
                                            -DENABLE_SMALL \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
											-DENABLE_CLIENT_SERVER \
											$(mutate_full) \
                                            -I. $(base_CPPFLAGS)

# Kitchen sink. Everything is enabled. Combo, Debug build
all_tests += multi.full.debug.combo
multi_full_debug_combo_CFLAGS    =          $(base_CFLAGS) $(mutate_full_CFLAGS)
multi_full_debug_combo_LDADD     =          $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
											$(mutate_full_LIBS)
multi_full_debug_combo_SOURCES   =          $(combo_sources)
multi_full_debug_combo_CPPFLAGS  =          -DENABLE_DEBUG \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
											-DENABLE_CLIENT_SERVER \
											$(mutate_full) \
                                            -I. $(base_CPPFLAGS)

# Kitchen sink. Everything is enabled, client only
all_tests += multiclient.full.ndebug.client
multiclient_full_ndebug_client_CFLAGS    =  $(base_CFLAGS) $(mutate_full_CFLAGS)
multiclient_full_ndebug_client_LDADD     =  $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
											$(mutate_full_LIBS)
multiclient_full_ndebug_client_SOURCES   =  $(combo_sources)
multiclient_full_ndebug_client_CPPFLAGS  =  -DNDEBUG \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
											-DENABLE_CLIENT_SERVER \
											-DENABLE_CLIENT_ONLY \
											$(mutate_full) \
                                            -I. $(base_CPPFLAGS)

if INTEGRATED_openvpn_le_2_3
# Ie, ENABLE_SSL is separate from ENABLE_CRYPTO
all_tests += multi.crypto-nossl.combo
multi_crypto_nossl_combo_CFLAGS =           $(base_CFLAGS)
multi_crypto_nossl_combo_LDADD =            $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1)
multi_crypto_nossl_combo_SOURCES =          $(server_sources)
multi_crypto_nossl_combo_CPPFLAGS =         -DENABLE_CLIENT_SERVER \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            -I. $(base_CPPFLAGS)

all_tests += multi.crypto-nossl-lzo.combo
multi_crypto_nossl_lzo_combo_CFLAGS =       $(base_CFLAGS)
multi_crypto_nossl_lzo_combo_LDADD =        $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            @LZO_LIBS@
multi_crypto_nossl_lzo_combo_SOURCES =      $(server_sources)
multi_crypto_nossl_lzo_combo_CPPFLAGS =     -DENABLE_CLIENT_SERVER \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_LZO) \
                                            -I. $(base_CPPFLAGS)

all_tests += multi.crypto-nossl-lzo-plugin.combo
multi_crypto_nossl_lzo_plugin_combo_CFLAGS =    $(base_CFLAGS)
multi_crypto_nossl_lzo_plugin_combo_LDADD =     $(base_LDADD) \
                                                $(mutate_CRYPTO_LIBS_1) \
                                                @DL_LIBS@ \
                                                @LZO_LIBS@
multi_crypto_nossl_lzo_plugin_combo_SOURCES =   $(server_sources)
multi_crypto_nossl_lzo_plugin_combo_CPPFLAGS =  -DENABLE_CLIENT_SERVER \
                                                $(mutate_ENABLE_CRYPTO_1) \
                                                $(mutate_ENABLE_LZO) \
                                                $(mutate_ENABLE_PLUGIN) \
                                                -I. $(base_CPPFLAGS)

else
all_tests += multi.crypto2-lzo.combo
multi_crypto2_lzo_combo_CFLAGS    = $(base_CFLAGS)
multi_crypto2_lzo_combo_LDADD     = $(base_LDADD) \
                                    $(mutate_CRYPTO_LIBS_2) \
                                    @LZO_LIBS@
multi_crypto2_lzo_combo_SOURCES   = $(server_sources)
multi_crypto2_lzo_combo_CPPFLAGS  = -DENABLE_CLIENT_SERVER \
                                    $(mutate_ENABLE_CRYPTO_2) \
                                    $(mutate_ENABLE_LZO) \
                                    -I. $(base_CPPFLAGS)

all_tests += multi.crypto2-lz4.combo
multi_crypto2_lz4_combo_CFLAGS    = $(base_CFLAGS)
multi_crypto2_lz4_combo_LDADD     = $(base_LDADD) \
                                    $(mutate_CRYPTO_LIBS_2) \
                                    @LZ4_LIBS@
multi_crypto2_lz4_combo_SOURCES   = $(server_sources)
multi_crypto2_lz4_combo_CPPFLAGS  = -DENABLE_CLIENT_SERVER \
                                    $(mutate_ENABLE_CRYPTO_2) \
                                    -DENABLE_LZ4 \
                                    -I. $(base_CPPFLAGS)

all_tests += multi.crypto2-lz.combo
multi_crypto2_lz_combo_CFLAGS    =  $(base_CFLAGS)
multi_crypto2_lz_combo_LDADD     =  $(base_LDADD) \
                                    $(mutate_CRYPTO_LIBS_2) \
        							$(mutate_SSL_LIBS_2) \
                                    @LZO_LIBS@ @LZ4_LIBS@
multi_crypto2_lz_combo_SOURCES   =  $(server_sources)
multi_crypto2_lz_combo_CPPFLAGS  =  -DENABLE_CLIENT_SERVER \
                                    $(mutate_ENABLE_CRYPTO_2) \
                                    $(mutate_ENABLE_SSL) \
                                    -DENABLE_LZ4 \
                                    $(mutate_ENABLE_LZO) \
                                    -I. $(base_CPPFLAGS)

all_tests += multiclient.crypto2-lzo-plugin.client
multiclient_crypto2_lzo_plugin_client_CFLAGS =  $(base_CFLAGS)
multiclient_crypto2_lzo_plugin_client_LDADD =   $(base_LDADD) \
                                                $(mutate_CRYPTO_LIBS_2) \
												$(mutate_SSL_LIBS_2) \
                                                @DL_LIBS@ \
                                                @LZO_LIBS@
multiclient_crypto2_lzo_plugin_client_SOURCES =     $(server_sources)
multiclient_crypto2_lzo_plugin_client_CPPFLAGS =    -DENABLE_CLIENT_SERVER \
                                                    -DENABLE_CLIENT_ONLY \
                                                    $(mutate_ENABLE_CRYPTO_2) \
                                                    $(mutate_ENABLE_SSL) \
                                                    $(mutate_ENABLE_LZO) \
                                                    $(mutate_ENABLE_PLUGIN) \
                                                    -I. $(base_CPPFLAGS)

endif

if !INTEGRATED_openvpn_2_0
if !INTEGRATED_openvpn_2_1
if !INTEGRATED_openvpn_2_2
# Tests with ssl2
all_tests += easy.ssl2.p2p
easy_ssl2_p2p_CFLAGS    =                       $(base_CFLAGS)
easy_ssl2_p2p_LDADD     =                       $(base_LDADD) \
                                                $(mutate_CRYPTO_LIBS_2) \
                                                $(mutate_SSL_LIBS_2)
easy_ssl2_p2p_SOURCES   =                       $(client_sources)
easy_ssl2_p2p_CPPFLAGS  =                       $(mutate_ENABLE_CRYPTO_2) \
                                                $(mutate_ENABLE_SSL) \
                                                -I. $(base_CPPFLAGS)

# Multi combo, only SSL #2 enabled, nothing else
all_tests += multi.ssl2.combo
multi_ssl2_combo_CFLAGS    =                    $(base_CFLAGS)
multi_ssl2_combo_LDADD     =                    $(base_LDADD) \
                                                $(mutate_CRYPTO_LIBS_2) \
                                                $(mutate_SSL_LIBS_2)
multi_ssl2_combo_SOURCES   =                    $(client_sources)
multi_ssl2_combo_CPPFLAGS  =                    $(mutate_ENABLE_CRYPTO_2) \
                                                $(mutate_ENABLE_SSL) \
                                                -DENABLE_CLIENT_SERVER \
                                                -I. $(base_CPPFLAGS)

# Kitchen sink. Everything is enabled, client only, with alternate SSL libs #2
all_tests += multiclient.full.ssl2.ndebug.client
multiclient_full_ssl2_ndebug_client_CFLAGS =    $(base_CFLAGS) $(mutate_full_CFLAGS)
multiclient_full_ssl2_ndebug_client_LDADD =     $(base_LDADD) \
                                                $(mutate_CRYPTO_LIBS_2) \
                                                $(mutate_SSL_LIBS_2) \
												$(mutate_full_LIBS)
multiclient_full_ssl2_ndebug_client_SOURCES =   $(combo_sources)
multiclient_full_ssl2_ndebug_client_CPPFLAGS =  -DNDEBUG \
                                                $(mutate_ENABLE_CRYPTO_2) \
                                                $(mutate_ENABLE_SSL) \
                                                $(mutate_ENABLE_LZO) \
                                                $(mutate_ENABLE_PLUGIN) \
                                                -DENABLE_CLIENT_SERVER \
                                                -DENABLE_CLIENT_ONLY \
												$(mutate_full) \
                                                -I. $(base_CPPFLAGS)
endif
endif
endif

# Enabled debugging is not supposed to modify behaviour, but sometimes
# active code is forgotten surrounded by #test ENABLE_DEBUG
# this test may help catch those.
all_tests +=  multi.debug.combo
multi_debug_combo_CFLAGS      =             $(base_CFLAGS)
multi_debug_combo_LDADD       =             $(base_LDADD) \
                                            $(mutate_CRYPTO_LIBS_1) \
                                            $(mutate_SSL_LIBS_1) \
                                            @DL_LIBS@ \
                                            @LZO_LIBS@
multi_debug_combo_SOURCES     =             $(server_sources)
multi_debug_combo_CPPFLAGS    =             -DENABLE_DEBUG \
                                            -DENABLE_CLIENT_SERVER \
                                            $(mutate_ENABLE_CRYPTO_1) \
                                            $(mutate_ENABLE_SSL) \
                                            $(mutate_ENABLE_LZO) \
                                            $(mutate_ENABLE_PLUGIN) \
                                            -I. $(base_CPPFLAGS)

check_PROGRAMS = $(all_tests)
endif

TESTS = $(check_PROGRAMS)
