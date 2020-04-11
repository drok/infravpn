#!/bin/bash
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

# TODO: This can be used as a test driver.
# It could receive the following args:
# -S "server config" -C "client config" -s <server binary> <client binary>

# It should run the server binary with the server config and attempt to
# use the client to connect to it, as a sanity test.

# The does-it-build test will run every built *.client with this script,
# thus testing that each build config can connect to the chosen server binary

AUTOMAKE_TEST_SKIPPED=77
AUTOMAKE_TEST_HARD_ERROR=99

fail() {
    >&2 echo "Fail: $1"
    exit 1;
}

do_test ()
{
    local srvopts=()
    local cltopts=()

    local cltbin srvbin srv_pid
    local uut uut_pid uut_version status applicable=1
    local opt OPTARG OPTIND=1

    while getopts ":s:c:S:C:V:" opt ; do
        case $opt in
        s) srvbin=$OPTARG
        ;;
        S) srvopts+=("$OPTARG")
        ;;
        c) cltbin=$OPTARG
        ;;
        C) cltopts+=("$OPTARG")
        ;;
        V) uut_version=$OPTARG
        ;;
        \?)     fatal "Invalid option: -$OPTARG"
                        ;;
        :)      fatal "Option -$OPTARG requires an argument in ${FUNCNAME[0]}."
                        ;;
                    esac
    done
    shift $((OPTIND-1))

    # Must know what version the UUT is supposed to be. The test itself is
    # broken if this is not given.
    [[ ${uut_version:+isset} ]] || exit "$AUTOMAKE_TEST_HARD_ERROR"

    # Assume uut is a client
    uut=$1
    [ -x "$uut" ] || fail "UUT $uut is not executable"

    if [[ ${srvbin:+isset} ]] ; then
	local cmdargs
	eval "cmdargs=(" "${srvopts[@]//\$/\\\$}" ")" || {
	    fatal "Mismatched escapes in srvopts[@]: '${srvopts[*]}'"
	}

	"$srvbin" "${cmdargs[@]}" &
	server_pid=$!
    fi
    
    local cmdargs
    eval "cmdargs=(" "${cltopts[@]//\$/\\\$}" ")" || {
	fatal "Mismatched escapes in ctlopts[@]: '${cltopts[*]}'"
    }
    "$uut" "${cmdargs[@]}" &

    uut_pid=$!

    status=0
    wait "$uut_pid" || status=$?

    if [[ ${srvbin:+isset} ]] ; then
	kill -QUIT "$server_pid"
	wait "$server_pid" || :
    fi

    case "$uut_version" in
	"OpenVPN "*)
			    [[ "$status" == 1 ]] || fail "Unexpected exit status $status"
	;;
	*)		    [[ "$status" == 0 ]] || fail "Unexpected exit status $status"
	;;
    esac

    # this simple test has no reason to be skipped, but this is how it would be
    # implemented; Do "unset applicable" where it's determined that
    # test is not applicable.
    [[ ${applicable:+isset} ]] || return "$AUTOMAKE_TEST_SKIPPED"

    :
}

do_test "$@"
