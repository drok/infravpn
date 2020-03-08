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

/*
 * These routines implement RFC4821 (Packetization Layer Path MTU discovery)
 * on top of the reliability layer, so the application can automatically
 * select maximum send frame size without requiring error-prone configuration.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "rfc4821.h"

#include "memdbg.h"

void
plpmtud_init (struct plpmtud *state, uint16_t start_mtu)
{
  dmsg(D_MTU_DEBUG, "PMTUD: Init MTU Discovery, start at %"PRIu16, start_mtu);

  ASSERT (!IS_INITIALIZED(state));
#if !defined(NDEBUG)
  state->is_init = true;
#endif

  state->pmtu = start_mtu;
  state->max_probe = state->upper_bound = 0xffff;
  
  /* This is important. On a new connection, start probing with the highest
   * MTU. Most likely the kernel will reject the send with EMSGSIZE, which
   * means the MTU to the host is smaller. No probe will be sent on the wire,
   * and this is quick.
   * 
   * If the kernel has communicated with the host, ICMP is not blocked, the
   * kernel may have a more accurate MTU estimate in its route cache, which
   * will be delivered via plpmtud_hint()
   * 
   * Then real probing starts with that estimate.
   */
  state->cursor =  state->upper_bound;
}

void
plpmtud_set_max_probe (struct plpmtud *state, uint16_t max_probe)
{
  state->max_probe = max_probe;
}

/* Restart discovery starting from the previously found results
 */
void
plpmtud_start (struct plpmtud *state)
{
  ASSERT (IS_INITIALIZED(state));
  ASSERT (state->active == PMTUD_DONE &&
       "Discovery cannot be restarted while in progress");

  dmsg(D_MTU_DEBUG, "PMTUD: Start PMTU Discovery from PMTU=%"PRIu16, state->pmtu);

  state->active = PMTUD_RESTING;
  state->cursor = state->max_probe;
  if (state->upper_bound > state->max_probe)
    state->upper_bound = state->max_probe;
}

/* Notification of received (single) probe ack.
 */
uint16_t
plpmtud_ack (struct plpmtud *state,
             uint16_t size)
{
  ASSERT (state != NULL);
  ASSERT (IS_INITIALIZED(state));
  ASSERT (state->active == PMTUD_INFLIGHT);
  ASSERT (size == state->cursor);

  /* 1st probe = big packet to discover interface MTU */
  if (size > state->upper_bound)
    {
    }

  else if (size == state->upper_bound)
    /* 2nd probe = upper bound previously discovered mtu+1 */
    {
      if (size != state->max_probe)
        {
          /* Scan above the upper_bound */
            state->cursor = size + (state->max_probe - size) /2;
            state->upper_bound = size + (state->max_probe - size + 1) /2;
        }
    }
  else
    /* subsequent probes. If Path MTU has decreased ... */
    {
      /* Bisect up to the last upper_bound */
      state->cursor = size + (state->upper_bound - size) / 2;
    }
  
  state->pmtu = size;

  if (state->cursor != size)
    state->active = PMTUD_RESTING;
  else
    state->active = PMTUD_DONE;

  dmsg(D_MTU_DEBUG, "PMTUD: Probe acked. Update PMTU=%"PRIu16" Next probe=%"PRIu16" %s",
       state->pmtu,
       state->cursor, state->active == PMTUD_DONE ? "DONE" : "RESTING");

  return state->pmtu;
}

/* When a probe is lost, call this to inform the state machine.
 */
bool
plpmtud_lostprobe (struct plpmtud *state,
                    uint16_t size)
{
  ASSERT (state != NULL);
  ASSERT (IS_INITIALIZED(state));
  ASSERT (size == state->cursor);
  ASSERT (state->active == PMTUD_INFLIGHT);

  /* 1st probe = big packet to discover interface MTU */
  if (size > state->upper_bound)
    {
      state->cursor = state->upper_bound;
    }

  else if (size == state->upper_bound && state->pmtu < state->max_probe)
    /* 2nd probe = upper bound previously discovered mtu+1 */
    {
      /* Check if previous PMTU is still good */
      state->cursor = state->pmtu;
    }

  else if (state->cursor > state->pmtu)
    /* subsequent probes. If Path MTU has increased ... */
    {
      /* Bisect down to the last good PMTU */
      state->cursor = size - (size - state->pmtu) / 2;
      state->upper_bound = size;
    }

  else
    /* subsequent probes. If Path MTU has decreased ... */
    {
      /* Bisect down to the threshold */
      state->cursor = size - (size - LINK_PACKETIZATION_THRESHOLD + 1 ) / 2;
      state->upper_bound = size;
      if (state->cursor == LINK_PACKETIZATION_THRESHOLD)
        state->pmtu = state->cursor;
    }

  if (state->cursor == size)
    {
      state->active = PMTUD_DONE;
    }
  else
    {
      state->active = PMTUD_RESTING;
    }
  
  dmsg(D_MTU_DEBUG, "PMTUD: Lost %"PRIu16"-byte probe. Path MTU <= %"PRIu16"."
                    " Next Probe = %"PRIu16" %s",
       size, state->upper_bound,
       state->cursor, state->active == PMTUD_DONE ? "DONE" : "RESTING");

  return (state->active == PMTUD_DONE);
}

/* Kernel gave us a hint EMSGSIZE on send() or such, meaning it failed to send
 * a packet due to MTU constraints.
 * The application should also cancel the probe timeout. The probe is lost.
 */
void
plpmtud_hint (struct plpmtud *state,  uint16_t mtu)
{
  ASSERT (IS_INITIALIZED(state));
#if defined(TEST_HARNESS)
  /* In the harness, hints should not come while not probing.
   * In deployment, hints can come any time (eg, the two hosts communicate
   * via another application causing the kernel to be informed of a PMTU change)
   * 
   * FIXME: Update the unit test to test this scenario.
   */
#endif

  dmsg(D_MTU_DEBUG, "PMTUD: Got hint: Path MTU <= %"PRIu16, mtu);

    {
      state->upper_bound = MAX(mtu, LINK_PACKETIZATION_THRESHOLD) + 1;
    }

    if (state->active == PMTUD_INFLIGHT)
    {
      if (state->pmtu > state->upper_bound)
        state->pmtu = state->upper_bound - 1;

      /* 1st probe = big packet to discover interface MTU */
      if (state->cursor > state->upper_bound)
        {
          /* If there is no search space above the THRESHOLD, don't search */
          if ( state->upper_bound > LINK_PACKETIZATION_THRESHOLD + 1)
            {
              /* check if previous pmtu is still valid */
              state->cursor = state->pmtu;
              state->active = PMTUD_RESTING;
            }
          else
            state->active = PMTUD_DONE;
        }

      else
        {
          /* hint MTU is larger than current cursor, it must be unrelated to
           * the probe. Do nothing. */
        }

    }
  else if (state->active == PMTUD_DONE)
    state->cursor = state->upper_bound - 1;

}

/* Accessor getting the current Path MTU 
 */
uint16_t
plpmtud_get_pmtu (const struct plpmtud *state)
{
  ASSERT(IS_INITIALIZED(state));
  dmsg(D_MTU_DEBUG, "PMTUD: Reported Path MTU=%"PRIu16, state->pmtu);
  return state->pmtu;
}

/* Probing Gate. Called when there is an opportunity to probe, responds
 * by configuring the buffer with the probe packet.
 */
bool
plpmtud_send_opportunity (struct plpmtud *state,
                          struct buffer *buf,
                          uint16_t overhead)
{
  ASSERT (IS_INITIALIZED(state));
  ASSERT (overhead < state->cursor);
  ASSERT (state->active != PMTUD_RESTING || state->cursor <= state->max_probe);

  if (state->active == PMTUD_RESTING)
    {
        state->active = PMTUD_INFLIGHT;
        buf_fill_incompressible (buf, state->cursor - overhead);
        dmsg(D_MTU_DEBUG, "PMTUD: send probe size=%"PRIu16" -overhead=%"PRIu16,
             state->cursor, overhead);
        return true;
    }
    
  return false;
}
