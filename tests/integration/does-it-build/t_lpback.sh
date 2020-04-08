#! /bin/sh
#
# t_lpback.sh - script to test OpenVPN's crypto loopback
# Copyright (C) 2005  Matthias Andree
# Copyright (C) 2014  Steffan Karger
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

set -eu

[[ ${#@} == 1 ]] || {
    echo "Usage: $0 <binary name>"
    exit 99
}
bin=${1}

echo -n "Check support for broken cipher mitigations ... "
if ! "$bin" | grep -q "SSL+mitigations" ; then
    echo "FAILED"
    exit 1
else
    echo "PASS"
fi

if [[ ${IMPLEMENTED_tls_crypt_2_5:+isset} ]] ; then
trap "rm -f key.$$ tc-server-key.$$ tc-client-key.$$ log.$$ ; trap 0 ; exit 77" 1 2 15
trap "rm -f key.$$ tc-server-key.$$ tc-client-key.$$ log.$$ ; exit 1" 0 3
else
trap "rm -f key.$$ log.$$ ; trap 0 ; exit 77" 1 2 15
trap "rm -f key.$$ log.$$ ; exit 1" 0 3
fi

# Get list of supported ciphers from openvpn --show-ciphers output
CIPHERS=$($bin --show-ciphers | \
            sed -e '/The following/,/^$/d' -e s'/ .*//' -e '/^[[:space:]]*$/d')

# Also test cipher 'none'
CIPHERS=${CIPHERS}$(printf "\nnone")

if [[ ${IMPLEMENTED_tls_crypt_2_5:+isset} ]] ; then
"$bin" --genkey secret key.$$
else
"$bin" --genkey --secret key.$$
fi
set +e

e=0
for cipher in ${CIPHERS}
do
    echo -n "Testing cipher ${cipher}... "
    ( "$bin" --test-crypto --secret key.$$ --cipher ${cipher} ) >log.$$ 2>&1
    if [ $? != 0 ] && ! grep -q "$cipher system implementation is faulty, and no mitigation is available" log.$$; then
        echo "FAILED"
        cat log.$$
        e=1
    else
        echo "OK"
    fi
done

if [[ ${IMPLEMENTED_tls_crypt_2_5:+isset} ]] ; then

echo -n "Testing tls-crypt-v2 server key generation..."
"$bin" \
    --genkey tls-crypt-v2-server tc-server-key.$$ >log.$$ 2>&1
if [ $? != 0 ] ; then
    echo "FAILED"
    cat log.$$
    e=1
else
    echo "OK"
fi

echo -n "Testing tls-crypt-v2 key generation (no metadata)..."
"$bin" --tls-crypt-v2 tc-server-key.$$ \
    --genkey tls-crypt-v2-client tc-client-key.$$ >log.$$ 2>&1
if [ $? != 0 ] ; then
    echo "FAILED"
    cat log.$$
    e=1
else
    echo "OK"
fi

# Generate max-length base64 metadata ('A' is 0b000000 in base64)
METADATA=""
i=0
while [ $i -lt 732 ]; do
    METADATA="${METADATA}A"
    i=$(expr $i + 1)
done
echo -n "Testing tls-crypt-v2 key generation (max length metadata)..."
"$bin" --tls-crypt-v2 tc-server-key.$$ \
    --genkey tls-crypt-v2-client tc-client-key.$$ "${METADATA}" \
    >log.$$ 2>&1
if [ $? != 0 ] ; then
    echo "FAILED"
    cat log.$$
    e=1
else
    echo "OK"
fi

rm key.$$ tc-server-key.$$ tc-client-key.$$ log.$$

else

rm key.$$ log.$$

fi
trap 0
exit $e
