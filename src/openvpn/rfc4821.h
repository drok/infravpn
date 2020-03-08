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


/**
 * @file
 * Packetization Layer Path MTU Discovery (based on RFC4821).
 */


#ifndef RFC4821_H
#define RFC4821_H

#include "basic.h"
#include "buffer.h"

/** @addtogroup rfc4821
 *  @{ */


#define PMTUD_SEARCH_QUANTUM 16 /**<  How close to real MTU will the search get
                                 *   before it stops trying to get closer?
                                 **/

/* What is the minimum MTU for which to packetize data?
 * If the Path MTU is smaller than this, packetize no larger than this.
 * The OS and routers should then do IP fragmentation.
 * This limits the overhead/payload ratio in low MTU scenarios.
 */
#if !defined(LINK_PACKETIZATION_THRESHOLD)
#define LINK_PACKETIZATION_THRESHOLD 100
#endif

/* Path Discovery will run every 10 minutes, as recommended by RFC 4821 s. 7.3
 * It can be overridden at build time for unit tests, etc.
 */
#if !defined(PMTUD_INTERVAL)
#define PMTUD_INTERVAL 600
#endif

/**
 * State of the MTU discovery.
 */
struct plpmtud
{
#if !defined(NDEBUG)
  bool is_init;
#endif

  enum {

    PMTUD_DONE = 0,
    PMTUD_RESTING,
    PMTUD_INFLIGHT,
  } active;

  /* Search space state */
  uint16_t  cursor;       /* Search cursor. Next MTU to probe. Valid when RESTING */
  uint16_t  pmtu;         /* Search lower bound. Current proven Path MTU minimum */
  uint16_t  upper_bound;  /* Search upper limit. Suspected to exceed Path MTU */
  uint16_t  max_probe;    /* Largest allowed probe size */
};

/**************************************************************************/
/** @name Functions for initialization and cleanup
 *  @{ */

/**
 * Initialize PMU discovery state.
 *
 * @param state PMTU discovery state context to be initialized.
 * @param start_pmtu Initial Path MTU for the first search to start at.
 * 
 */
void plpmtud_init (struct plpmtud *state, uint16_t start_mtu);

/**
 * Set maximum probe size. Used in cases where there is a known limit to the
 * peer's ability to correctly ack probes.
 * 
 * In legacy openvpn software, the reliable layer would ACK datagrams before
 * checking their HMAC, and the read buffer size was set by the user, causing
 * it to truncate any datagrams larger than the user configured size.
 * The combination of truncated datagrams, and premature ACK-ing would cause
 * the estimated MTU (based on received ACKs) to be larger than the peer is
 * able to receive correctly, if the Path MTU > user configured read buffer size
 *
 * @param state PMTU discovery state context to be initialized.
 * @param max_probe Maximum probe size to send
 */
void plpmtud_set_max_probe (struct plpmtud *state, uint16_t max_probe);

/** @} name Functions for initialization and cleanup */


/**************************************************************************/
/** @name Functions for inserting incoming packets
 *  @{ */

/* Restart discovery starting from the previously found results */
void
plpmtud_start (struct plpmtud *state);

/** @} name Functions for inserting incoming packets */


/**************************************************************************/
/** @name Functions for extracting outgoing packets
 *  @{ */

/** Accessor getting the current Path MTU
 *
 * @param state PMTUD state object
 * @return the current best Path MTU estimate 
 */
uint16_t 
plpmtud_get_pmtu (const struct plpmtud *state);

/* Probing Gate. Called when there is an opportunity to probe, responds
 * by configuring the buffer with the probe packet.
 * 
 * @param state PMTUD state object
 * @param buf Buffer that can be sent as a probe.
 * @param pid Packet id for the probe packet. Used only for runtime error checking.
 * @param overhead Space needed for IP headers + UDP headers + openvpn's control
 *                  packet overhead with no acks. (ie, P_OPCODE_LEN+SID_SIZE+
 *                  ACK_SIZE(0) + hmac_ctx_size(tls_auth encrypt hmac)
 * 
 * @return false if a probe is not needed, true if this buffer should be sent as
 *  probe.
 */

bool plpmtud_send_opportunity (struct plpmtud *state,
                                     struct buffer *buf,
                                     uint16_t overhead);

/**
 * Notification that a probe was acked.
 * Called when reliable_send_purge() is called for an already
 * acked packet_id.
 * @param state - PMTUD search state
 * @param pid     Probe/Packet id being acked
 * @param size    Probe size
 * @return        new MTU if different then previous, 0 if no MTU change.
 */

uint16_t
plpmtud_ack (struct plpmtud *state,
             uint16_t size);

/** Notification that the timeout for a previously sent probe was reached, w/o
 * acknowledgement, or sending failed due to EMSGSIZE (kernel's tracked PMTU)
 * 
 * @param state - PMTUD search state
 * @param pid     Probe/Packet id being acked
 * @param size    Size of the lost probe
 * 
 * @return true if discovery is finished.
 */
bool
plpmtud_lostprobe (struct plpmtud *state,
                   uint16_t size);

/**
 * Notification (from the kernel) of an updated path MTU.
 * Called when the kernel receives a PTB (packet too big)
 * 
 */
void
plpmtud_hint (struct plpmtud *state, uint16_t mtu);

/**
 * Returns discovered Path MTU
 *
 * @param rel The reliable structured to check.
 *
 * @return The interval in seconds until the earliest resend attempt
 *     of the outgoing packets stored in the \a rel reliable structure. If
 *     the next time for attempting resending of one or more packets has
 *     already passed, this function will return 0.
 */
uint16_t
plpmtud_get_mtu (const struct plpmtud *state);

/** @} name Functions for extracting outgoing packets */


/**************************************************************************/
/** @name Miscellaneous functions
 *  @{ */

#if 0
/**
 * Determine how many seconds until the earliest resend should
 *     be attempted.
 *
 * @param state The PMTUD state to check.
 *
 * @return The interval in seconds until the earliest resend attempt
 *     of the outgoing packets stored in the \a rel reliable structure. If
 *     the next time for attempting resending of one or more packets has
 *     already passed, this function will return 0.
 */
interval_t
plpmtud_timeout (const struct plpmtud *state);
#endif

/**
 * Is PMTUD ready to send a probe now?
 */

static inline bool
plpmtud_can_send (const struct plpmtud *state)
{
  return state->active == PMTUD_RESTING;
}

/** @} name Miscellaneous functions */ 

/** @} addtogroup rfc4821 */



#endif /* RFC4821_H */


