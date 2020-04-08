#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

AUTOMAKE_OPTIONS = parallel-tests

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

SUBDIRS =

test_scripts = t_client.sh
if ENABLE_CRYPTO
test_scripts += t_lpback.sh t_cltsrv.sh
endif

if ENABLE_UNITTESTS

if UNIT_TESTED_base64
SUBDIRS += unit/base64
endif

if UNIT_TESTED_tls_crypt
SUBDIRS += unit/tls_crypt
endif

if UNIT_TESTED_rfc4821
SUBDIRS += unit/rfc4821
endif

if UNIT_TESTED_mtu
SUBDIRS += unit/mtu
endif

if UNIT_TESTED_buffer
SUBDIRS += unit/buffer
endif

if UNIT_TESTED_sitnl
SUBDIRS += integration/sitnl
endif

if ENABLE_UNITTESTS_ALL
SUBDIRS += integration/does-it-build
endif


TESTS_ENVIRONMENT = top_srcdir="$(top_srcdir)"

TESTS = $(test_scripts)

endif

dist_noinst_SCRIPTS = \
	$(test_scripts) \
	t_cltsrv-down.sh \
	update_t_client_ips.sh

dist_noinst_DATA = \
	t_client.rc-sample
