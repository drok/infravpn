/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2020 Radu Hociung <radu.ovpndev@ohmi.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef QUIRKS_H
#define QUIRKS_H

/* This file represents an inter-operation map. It is used to manage and test
 * feature obsolescence
 * 
 * It documents quirks or bugs found in earlier versions of the software.
 * This enables later versions to clearly document "odd" code which is a
 * workaround to handle compatibility with buggy versions.
 * 
 * Also, it documents which versions of old software are affected, such that
 * in the future, should the maintainers consider cleaning up old
 * hacks/workarounds, it is clear which software versions or old functionality
 * will be rendered incompatible.
 * 
 * Furthermore, it enables integration testing of "cleaned-up" future versions.
 * Old workarounds can be ifdef'ed out by building a dry-run version of the sw
 * with, e.g. "-DOBSOLETE_OPENVPN_2_0 -DOBSOLETE_OPENVPN_2_1" to remove
 * workarounds that only exist to support those two versions, and then testing
 * the dry-run software against old, but newer than 2.1 versions, to verify
 * that interop is not affected by removing the workarounds.
 * 
 * It includes handling a fork of the software, here called "ovpn", whereby
 * either project can document which workarounds exist to handle bugs in the 
 * fork (or parent), and also to test how compatibility with the forks/parents
 * would be affected by obsoleting support for some version. For all practical
 * purposes, a "fork" or "parent" is just another older version of the same
 * software.
 */

/* ----------------------- Functional Description ----------------------------
 * The context2 struct contains a field named bugfixes which contains bit-maps
 * indicating up to 31 bugfixes implemented by the peer for v2 protocols.
 *
 * The bugfixes map is exchanged in the HARD_RESET message that initiates every
 * connection; the "packet_id" field is used for this purpose. Legacy versions
 * use a hardcoded value of "0" for the packet_id field, which is taken to mean
 * "no bugfixes implemented".
 * 
 * Every quirk is defined by a compile-time #define, and a run-time macro;
 *
 * The #define sets which bit out of the bugfix map is assigned to advertising
 * the workaround to the peer, and conversely detecting whether peer implements
 * a bugfix. (eg, HANDLE_MANUAL_TRANSMISSION_V2)
 * 
 * The runtime macro expands to an if statement that checks the bugfixes map
 * advertised by the peer, and if the bugfix is not advertised, it executes the
 * following statement or block. (Eg. WORKAROUND(MANUAL_TRANSMISSION, c))
 * 
 * The name of the #define specifying the detection bit is followed by a suffix
 * indicating the protocol version. The current protocol is V2. For the next
 * protocol version, the bugs applicable to that protocol should sport a V3
 * suffix.
 *
 * 
 * #define HANDLE_MANUAL_TRANSMISSION_V2
 * Every WORKAROUND macro is a detection bit (if that bit is set in
 * context.peer_bugfixes, it means the peer has a bugfix, and executing the
 * workaround code should not be done).
 * 
 * See example usage below.
 * 
 */

/* Example usage:
 * This generic workaround is for deprecated manual transmissions.
 * 
 * The instance talking with a peer that only implements a manual transmission
 * algorithm, needs to be told to shift gears one at a time, otherwise it
 * crashes.
 * 
 * The state-of-the-art implementation uses automatic transmissions, including
 * the detail of shifting sequence. Therefore, we only need to tell it
 * what gear we want, it takes care of the minutia.
 *
 * #if defined(HANDLE_MANUAL_TRANSMISSION_V2)
 * WORKAROUND(MANUAL_TRANSMISSION, c)
 *   {
 *     // Do something special if the peer has the bug, and needs a workaround.
 *     // This interface is "deprecated".
 *
 *     if (current_gear > want_gear)
 *       {
 *         for (int i = current_gear ; i > want_gear ; i--) shift_down();
 *       }
 *     else if (current_gear < want_gear)
 *       {
 *         for (int i = current_gear ; i < want_gear ; i++) shift_up();
 *       }
 *   }
 * else
 * #endif
 *   {
 *      // Act normally, as if talking with a peer that has the bugfix implemented
 *      // and knows how to handle "AUTOMATIC"
 *      // This is the "state-of-the-art" interface.
 *
 *      automatic_shift (want_gear);
 *   }
 * 
 * To 
 */



/* In the future, when the V3 protocol is introduced, the WORKAROUND macro
 * will be changed to detect which protocol the peer speaks and check the
 * appropriate bugfix map (there will be separate maps for each proto version):
 */
#if 1
#define WORKAROUND(bugfixes, bugname) if (  \
    !(bugfixes)->v2 & (WORKAROUND_V2_##bugname) \
    )
#else

#define WORKAROUND(context, bugname) if (  \
    (((context)->c2.proto == PROTOCOL_V2 && \
            !(bugfixes)->v2 & (WORKAROUND_V2_##bugname))) || \
    (((context)->c2.proto == PROTOCOL_V3 && \
            !(bugfixes)->v3 & (WORKAROUND_V3_##bugname))) \
    )
#endif

#if defined(OBSOLETE_ALL)
/* Use -DOBSOLETE_ALL for closed deployments. All known workarounds will be
 * removed.
 */
#define OBSOLETE_OPENVPN_2_0
#define OBSOLETE_OPENVPN_2_1
#define OBSOLETE_OPENVPN_2_2
#define OBSOLETE_OPENVPN_2_3
#define OBSOLETE_OPENVPN_2_4
#define OBSOLETE_OPENVPN_2_5
#define OBSOLETE_OPENVPN_ALL

#define OBSOLETE_OVPN_1_0
#define OBSOLETE_OVPN_ALL
#endif

#if !defined(OBSOLETE_OPENVPN_ALL)
/* Quirks/bugs that exist in the current OpenVPN, and require special code
 * for backwards compatibility
 */

/*  ---------------------- UNRELIABLE_RELIABLE ---------------------------------
 * Issue Tracker: https://github.com/drok/ovpn/issues/6
 * 
 * The reliable layer is not reliable.
 * It ACKs incoming packets before checking their HMAC, so corrupt/truncated
 * packets are acked, and should not be. The peer causes this truncation itself
 * by reading from the link in a buffer that is too small.
 * 
 * One of the effects is that while PMTU probing such a buggy peer, the probes
 * must be limited to no greater than it's receiving buffer size. Fortunately,
 * these versions use the same buffer size for sending and for receiving, so
 * the size of the receive buffer can be iteratively guessed by keeping track
 * of the largest packet received from them.
 * 
 * This quirk is also synonym with "user-controlled-buffers", "fixed MTU",
 * "limited udp datagrams"
 */
#define UNRELIABLE_RELIABLE_V2 (1<<0)

#define OPENVPN_ALL_BUGFIXES(X) \
            X(UNRELIABLE_RELIABLE, UNRELIABLE_RELIABLE_V2)


#endif


#if !defined(OBSOLETE_OPENVPN_2_5)
/* Quirks/bugs that existed in 2.5 but were fixed after, and require special code
 * for backwards compatibility
 */
#define OPENVPN_2_5_BUGFIXES(X)

#else
#define OPENVPN_2_5_BUGFIXES(X)
#endif

#if !defined(OBSOLETE_OPENVPN_2_4)
/* Quirks/bugs that existed in 2.4 but were fixed after, and require special code
 * for backwards compatibility
 */
#define OPENVPN_2_4_BUGFIXES(X)

#else
#define OPENVPN_2_4_BUGFIXES(X)
#endif

#if !defined(OBSOLETE_OPENVPN_2_3)
/* Quirks/bugs that existed in 2.3 but were fixed after, and require special code
 * for backwards compatibility
 */
#define OPENVPN_2_3_BUGFIXES(X)

#else
#define OPENVPN_2_3_BUGFIXES(X)
#endif

#if !defined(OBSOLETE_OPENVPN_2_2)
/* Quirks/bugs that existed in 2.2 but were fixed after, and require special code
 * for backwards compatibility
 */
#define OPENVPN_2_2_BUGFIXES(X)

#else
#define OPENVPN_2_2_BUGFIXES(X)
#endif

#if !defined(OBSOLETE_OPENVPN_2_1)
/* Quirks/bugs that existed in 2.1 but were fixed after, and require special code
 * for backwards compatibility
 */
#define OPENVPN_2_1_BUGFIXES(X)

#else
#define OPENVPN_2_1_BUGFIXES(X)
#endif

#if !defined(OBSOLETE_OPENVPN_2_0)
/* Quirks/bugs that exited in 2.0 but were fixed after, and require special code
 * for backwards compatibility
 */
#define OPENVPN_2_0_BUGFIXES(X)

#else
#define OPENVPN_2_0_BUGFIXES(X)
#endif

#if !defined(OBSOLETE_OVPN_ALL)
/* Quirks/bugs that exist in the current oVPN, and require special code
 * for backwards compatibility
 */
#define OVPN_ALL_BUGFIXES(X)

#else
#define OVPN_ALL_BUGFIXES(X)
#endif

#if !defined(OBSOLETE_OVPN_1_0)
/* Quirks/bugs that existed in 1.0 but were fixed after, and require special code
 * for backwards compatibility
 */
#define OVPN_1_0_BUGFIXES(X)

#else
#define OVPN_1_0_BUGFIXES(X)
#endif

#define BUGFIXES_V2(X) \
    OPENVPN_ALL_BUGFIXES(X) \
    OPENVPN_2_5_BUGFIXES(X) \
    OPENVPN_2_4_BUGFIXES(X) \
    OPENVPN_2_3_BUGFIXES(X) \
    OPENVPN_2_2_BUGFIXES(X) \
    OPENVPN_2_1_BUGFIXES(X) \
    OPENVPN_2_0_BUGFIXES(X) \
    OVPN_ALL_BUGFIXES(X) \
    OVPN_1_0_BUGFIXES(X)

#define BUGFIXES_V3(X)

#define DEFINE_ENUM_V2(name, value) WORKAROUND_V2_##name = value,
#define DEFINE_ENUM_V3(name, value) WORKAROUND_V3_##name = value,
#define DEFINE_BITMAP(name, value) | value
#define DEFINE_QUIRKNAMES(name, value) case value : return #name;

/* Enums are defined to detect when bugs are assigned conflicting bits in the
 * future.
 * In that case, this will cause a compile-time error.
 */
enum Bugfix_V2 {
    UNMANAGED_BUGS_V2 = 0,
    BUGFIXES_V2(DEFINE_ENUM_V2)
};

enum Bugfix_V3 {
    UNMANAGED_BUGS_V3 = 0,
    BUGFIXES_V3(DEFINE_ENUM_V3)
};

/* At version 2 of the protocol, quirk management used the packet_id_type
 * (uint32_t) to advertise capability.
 * At version 2 of the protocol, packet_id_type was uint32_t
 */
typedef uint32_t quirks_v2_type;

struct quirks {
  /* Peer's advertised fixed bugs */
  /* The '1' bits indicate bugs that the peer fixes, '0' indicate still existing
   * bugs/quirks
   */
  quirks_v2_type v2;
  
  /* add me when the first bug in version 3 proto that requires workarounds
   * is found
   */
  /* quirks_v3_type v3; */

};

#endif




