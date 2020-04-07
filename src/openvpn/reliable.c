/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
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
 * These routines implement a reliability layer on top of UDP,
 * so that SSL/TLS can be run over UDP.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_SSL)

#include "buffer.h"
#include "error.h"
#include "common.h"
#include "reliable.h"

#include "memdbg.h"

/*
 * verify that test - base < extent while allowing for base or test wraparound
 */
static inline bool
reliable_pid_in_range1 (const packet_id_type test,
			const packet_id_type base,
			const unsigned int extent)
{
  if (test >= base)
    {
      if (test - base < extent)
	return true;
    }
  else
    {
      if ((test+0x80000000u) - (base+0x80000000u) < extent)
	return true;
    }

  return false;
}

/*
 * verify that test < base + extent while allowing for base or test wraparound
 */
static inline bool
reliable_pid_in_range2 (const packet_id_type test,
			const packet_id_type base,
			const unsigned int extent)
{
  if (base + extent >= base)
    {
      if (test < base + extent)
	return true;
    }
  else
    {
      if ((test+0x80000000u) < (base+0x80000000u) + extent)
	return true;
    }

  return false;
}

/*
 * verify that p1 < p2  while allowing for p1 or p2 wraparound
 */
static inline bool
reliable_pid_lt (const packet_id_type p1,
		  const packet_id_type p2)
{
  return !reliable_pid_in_range1 (p1, p2, 0x80000000u);
}

/* check if a particular packet_id is present in ack */
static inline bool
reliable_ack_packet_id_present (struct reliable_ack *ack, packet_id_type pid)
{
  int i;
  for (i = 0; i < ack->len; ++i)
    if (ack->packet_id[i] == pid)
      return true;
  return false;
}

/* get a packet_id from buf */
bool
reliable_ack_read_packet_id (struct buffer *buf, packet_id_type *pid)
{
  packet_id_type net_pid;

  if (buf_read (buf, &net_pid, sizeof (net_pid)))
    {
      *pid = ntohpid (net_pid);
      dmsg (D_REL_DEBUG, "ACK read ID " packet_id_format " (buf->len=%d)",
	   (packet_id_print_type)*pid, buf->len);
      return true;
    }

  dmsg (D_REL_LOW, "ACK read ID FAILED (buf->len=%d)", buf->len);
  return false;
}

/* acknowledge a packet_id by adding it to a struct reliable_ack */
bool
reliable_ack_acknowledge_packet_id (struct reliable_ack *ack, packet_id_type pid)
{
  if (!reliable_ack_packet_id_present (ack, pid) && ack->len < RELIABLE_ACK_SIZE)
    {
      ack->packet_id[ack->len++] = pid;
      dmsg (D_REL_DEBUG, "ACK acknowledge ID " packet_id_format " (ack->len=%d)",
	   (packet_id_print_type)pid, ack->len);
      return true;
    }

  dmsg (D_REL_LOW, "ACK acknowledge ID " packet_id_format " FAILED (ack->len=%d)",
       (packet_id_print_type)pid, ack->len);
  return false;
}

/* read a packet ID acknowledgement record from buf into ack */
bool
reliable_ack_read (struct reliable_ack * ack,
		   struct buffer * buf, const struct session_id * sid)
{
  struct gc_arena gc = gc_new ();
  int i;
  uint8_t count;
  packet_id_type net_pid;
  packet_id_type pid;
  struct session_id session_id_remote;

  if (!buf_read (buf, &count, sizeof (count)))
    goto error;
  for (i = 0; i < count; ++i)
    {
      if (!buf_read (buf, &net_pid, sizeof (net_pid)))
	goto error;
      if (ack->len >= RELIABLE_ACK_SIZE)
	goto error;
      pid = ntohpid (net_pid);
      ack->packet_id[ack->len++] = pid;
    }
  if (count)
    {
      if (!session_id_read (&session_id_remote, buf))
	goto error;
      if (!session_id_defined (&session_id_remote) ||
	  !session_id_equal (&session_id_remote, sid))
	{
	  dmsg (D_REL_LOW,
	       "ACK read BAD SESSION-ID FROM REMOTE, local=%s, remote=%s",
	       session_id_print (sid, &gc), session_id_print (&session_id_remote, &gc));
	  goto error;
	}
    }
  gc_free (&gc);
  return true;

error:
  gc_free (&gc);
  return false;
}

/* write a packet ID acknowledgement record to buf, */
/* removing all acknowledged entries from ack */
bool
reliable_ack_write (struct reliable_ack * ack,
		    struct buffer * buf,
		    const struct session_id * sid, int max, bool prepend)
{
  int i, j;
  uint8_t n;
  struct buffer sub;

  n = ack->len;
  if (n > max)
    n = max;
  sub = buf_sub (buf, ACK_SIZE(n), prepend);
  if (!BDEF (&sub))
    goto error;
  ASSERT (buf_write (&sub, &n, sizeof (n)));
  for (i = 0; i < n; ++i)
    {
      packet_id_type pid = ack->packet_id[i];
      packet_id_type net_pid = htonpid (pid);
      ASSERT (buf_write (&sub, &net_pid, sizeof (net_pid)));
      dmsg (D_REL_DEBUG, "ACK write ID " packet_id_format " (ack->len=%d, n=%d)", (packet_id_print_type)pid, ack->len, n);
    }
  if (n)
    {
      ASSERT (session_id_defined (sid));
      ASSERT (session_id_write (sid, &sub));
      for (i = 0, j = n; j < ack->len;)
	ack->packet_id[i++] = ack->packet_id[j++];
      ack->len = i;
    }

  return true;

error:
  return false;
}

/* print a reliable ACK record coming off the wire */
const char *
reliable_ack_print (struct buffer *buf, bool verbose, struct gc_arena *gc)
{
  int i;
  uint8_t n_ack;
  struct session_id sid_ack;
  packet_id_type pid;
  struct buffer out = alloc_buf_gc (256, gc);

  buf_printf (&out, "[");
  if (!buf_read (buf, &n_ack, sizeof (n_ack)))
    goto done;
  for (i = 0; i < n_ack; ++i)
    {
      if (!buf_read (buf, &pid, sizeof (pid)))
	goto done;
      pid = ntohpid (pid);
      buf_printf (&out, " " packet_id_format, (packet_id_print_type)pid);
    }
  if (n_ack)
    {
      if (!session_id_read (&sid_ack, buf))
	goto done;
      if (verbose)
	buf_printf (&out, " sid=%s", session_id_print (&sid_ack, gc));
    }

 done:
  buf_printf (&out, " ]");
  return BSTR (&out);
}

/* Calculate the amount of space in bytes that are needed to transmit
 * a given number of acks withing a single frame.
 */
int
reliable_ack_get_frame_extra(int n_acks)
{
  return ACK_SIZE(n_acks);
}

static void
reliable_update_mtu(struct send_reliable *rel, struct frame *frame, size_t mtu)
{
    frame_set_mtu (frame, mtu);
    reliable_realloc(rel, frame_get_link_bufsize (frame));
    /* Other buffers needing resize:
     * aux_buf
     * encrypt_buf
     * decrypt_buf
     * frame_master.outgoing
     * frame_master.outgoing_return
     */
    frame_print (frame, D_MTU_INFO, "Updated PMTU:");
}

/*
 * struct reliable member functions.
 */

void
reliable_send_init (struct send_reliable *rel, int buf_size, int offset)
{
  int i;

  CLEAR (*rel);

  rel->offset = offset;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct send_reliable_entry *e = &rel->array[i];
      e->buf = alloc_buf (buf_size);
      ASSERT (buf_init (&e->buf, offset));
    }
  plpmtud_init (&rel->pmtud_state, LINK_MTU_STARTUP);
}

void
reliable_rec_init (struct rec_reliable *rel, int buf_size)
{
  int i;

  CLEAR (*rel);

  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct rec_reliable_entry *e = &rel->array[i];
      e->buf = alloc_buf (buf_size);
      ASSERT (buf_init (&e->buf, 0));
    }
}

void
reliable_send_free (struct send_reliable *rel)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct send_reliable_entry *e = &rel->array[i];
      free_buf (&e->buf);
    }
}

void
reliable_rec_free (struct rec_reliable *rel)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct rec_reliable_entry *e = &rel->array[i];
      free_buf (&e->buf);
    }
}

void
reliable_realloc (struct send_reliable *rel, int buf_size)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      realloc_buf(&rel->array[i].buf, buf_size);
    }
}

/* no active buffers? */
bool
reliable_empty (const struct send_reliable *rel)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      const struct send_reliable_entry *e = &rel->array[i];
      if (e->active >= REL_ACTIVE)
	return false;
    }
  return true;
}

bool
reliable_send_lost (struct send_reliable *rel, struct buffer *buf,
                    struct frame *frame)
{
  int i;
  bool done = false;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct send_reliable_entry *e = &rel->array[i];
      if (buf->data == e->buf.data)
	{
          /* In this version of openvpn, only probes can be lost. */
          ASSERT (e->active == REL_PMTUD_PROBE);
          done = plpmtud_lostprobe (&rel->pmtud_state,
                 buf->len + frame_get_link_encapsulation(frame));
          /* only ACKED buffers can be used as PROBE, revert to ack
           when lost, so they can be reused for another probe */

          if (done)
            reliable_update_mtu(rel, frame, plpmtud_get_pmtu(&rel->pmtud_state));

          e->active = REL_ACKED;
          return done;
	}
    }
  ASSERT (0 && "Cannot lose an unknown buffer");
}

/* del acknowledged items from send buf */
void
reliable_send_purge (struct send_reliable *rel, struct reliable_ack *ack,
                     struct frame *frame)
{
  int i, j;
  int ret = 0;
  for (i = 0; i < ack->len; ++i)
    {
      packet_id_type pid = ack->packet_id[i];
      for (j = 0; j < SIZE(rel->array); ++j)
	{
	  struct send_reliable_entry *e = &rel->array[j];
	  if (e->active >= REL_ACTIVE && e->packet_id == pid)
	    {
              if (e->active == REL_PMTUD_PROBE)
                {
                  unsigned int pmtu;
                  /* e->buf does not contain the auth data added by the auth layer in
                   * write_control_auth(), but contains the packet_id added by
                   * the reliable layer in reliable_mark_active_outgoing().
                   * compensate by adding to the acked size the IP, UDP and AUTH
                   * layer bytes, but not the packet_id
                   */
                  pmtu = plpmtud_ack (&rel->pmtud_state,
                                    e->buf.len + frame_get_reliable_encapsulation(frame,0));

                  reliable_update_mtu(rel, frame, pmtu);
                }
	      dmsg (D_REL_DEBUG,
		   "ACK received for pid %s" packet_id_format ", deleting from send buffer",
                   e->active == REL_PMTUD_PROBE ? "p" : "",
		   (packet_id_print_type)pid);
#if 0
	      /* DEBUGGING -- how close were we timing out on ACK failure and resending? */
	      {
		if (e->next_try)
		  {
		    const interval_t wake = e->next_try - now;
		    msg (M_INFO, "ACK " packet_id_format ", wake=%d", pid, wake);
		  }
	      }
#endif
             e->active = REL_ACKED;
	      break;
	    }
	}
    }
}

/* print the current sequence of active packet IDs */
static const char *
reliable_print_send_ids (const struct send_reliable *rel, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  int i;

  buf_printf (&out, "[" packet_id_format "]", (packet_id_print_type)rel->packet_id);
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      const struct send_reliable_entry *e = &rel->array[i];
      if (e->active >= REL_ACTIVE)
	buf_printf (&out, " " packet_id_format, (packet_id_print_type)e->packet_id);
    }
  return BSTR (&out);
}

static const char *
reliable_print_rec_ids (const struct rec_reliable *rel, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  int i;

  buf_printf (&out, "[" packet_id_format "]", (packet_id_print_type)rel->packet_id);
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      const struct rec_reliable_entry *e = &rel->array[i];
      if (e->active)
	buf_printf (&out, " %s" packet_id_format,
                 e->active == REL_PMTUD_PROBE ? "p" : "",
                 (packet_id_print_type)e->packet_id);
    }
  return BSTR (&out);
}

/* true if at least one free buffer available */
bool
reliable_can_get (const struct rec_reliable *rel)
{
  struct gc_arena gc = gc_new ();
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      const struct rec_reliable_entry *e = &rel->array[i];
      if (!e->active)
	return true;
    }
  dmsg (D_REL_LOW, "ACK no free receive buffer available: %s", reliable_print_rec_ids (rel, &gc));
  gc_free (&gc);
  return false;
}

/* make sure that incoming packet ID isn't a replay */
bool
reliable_not_replay (const struct rec_reliable *rel, packet_id_type id)
{
  struct gc_arena gc = gc_new ();
  int i;
  if (reliable_pid_lt (id, rel->packet_id))
    goto bad;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      const struct rec_reliable_entry *e = &rel->array[i];
      if (e->active && e->packet_id == id)
	goto bad;
    }
  gc_free (&gc);
  return true;

 bad:
  dmsg (D_REL_DEBUG, "ACK " packet_id_format " is a replay: %s", (packet_id_print_type)id, reliable_print_rec_ids (rel, &gc));
  gc_free (&gc);
  return false;
}

/* make sure that incoming packet ID won't deadlock the receive buffer */
bool
reliable_wont_break_sequentiality (const struct rec_reliable *rel, packet_id_type id)
{
  struct gc_arena gc = gc_new ();

  const int ret = reliable_pid_in_range2 (id, rel->packet_id, SIZE(rel->array));

  if (!ret)
    {
      dmsg (D_REL_LOW, "ACK " packet_id_format " breaks sequentiality: %s",
	   (packet_id_print_type)id, reliable_print_rec_ids (rel, &gc));
    }

  dmsg (D_REL_DEBUG, "ACK RWBS rel->size=%zu rel->packet_id=%08x id=%08x ret=%d\n", SIZE(rel->array), rel->packet_id, id, ret);

  gc_free (&gc);
  return ret;
}

/* grab a free buffer */
struct buffer *
reliable_get_rec_buf (struct rec_reliable *rel)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct rec_reliable_entry *e = &rel->array[i];
      if (!e->active)
	{
	  ASSERT (buf_init (&e->buf, 0));
	  return &e->buf;
	}
    }
  return NULL;
}

/* grab a free buffer, fail if buffer clogged by unacknowledged low packet IDs
 * Will reuse an ACKED buffer that is still in ackable range.
 */
struct buffer *
reliable_get_buf_output_sequenced (struct send_reliable *rel)
{
  unsigned int i;
  unsigned int freshest_ack_age = SIZE(rel->array);
  struct buffer *ret = NULL;

  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct send_reliable_entry *e = &rel->array[i];

      if (e->active >= REL_ACTIVE)
	{
          ASSERT (rel->packet_id - e->packet_id <= SIZE(rel->array) &&
              "No packets older than RELIABLE_N_SEND_BUFFERS can linger in the resend queue");
          if (rel->packet_id - e->packet_id == SIZE(rel->array))
            return NULL;
	}
      else if (e->active == REL_ACKED)
        {
          /* Use up freshest ACKED buffers first, so if they're needed for PMTU
           * probing, reliable traffic is not held up until the probe is
           * resolved.
           * This leaves the other, older ACKED buffers available for reliable
           * traffic.
           */
          if (rel->packet_id - e->packet_id <= freshest_ack_age)
            {
              ret = &e->buf;
              freshest_ack_age = rel->packet_id - e->packet_id;
            }
        }
      else if (ret == NULL)
        ret = &e->buf;
    }

  if (ret != NULL)
    {
      bool success = buf_init (ret, rel->offset);
      ASSERT (success);
    }
  return ret;
}

/* get active buffer for next sequentially increasing key ID */
struct buffer *
reliable_get_buf_sequenced (struct rec_reliable *rel)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct rec_reliable_entry *e = &rel->array[i];
      if (e->active && e->packet_id == rel->packet_id)
	{
	  return &e->buf;
	}
    }
  return NULL;
}

void reliable_renumber (struct send_reliable *rel, int offset)
{
  int i;
  packet_id_type net_pid;

  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct send_reliable_entry *e = &rel->array[i];
      if (e->active >= REL_ACTIVE)
	{
          e->packet_id += offset;
          e->next_try = now;
          
	  net_pid = htonpid (e->packet_id);
          buf_advance(&e->buf, sizeof (net_pid));
          buf_write_prepend (&e->buf, &net_pid, sizeof (net_pid));
	}
    }
  rel->packet_id += offset;
}

/* return true if reliable_send would return a non-NULL result */
bool
reliable_can_send (struct send_reliable *rel, struct frame *frame)
{
  struct gc_arena gc = gc_new ();
  int i;
  int n_active = 0, n_current = 0;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct send_reliable_entry *e = &rel->array[i];
      if (e->active == REL_ACTIVE)
	{
	  ++n_active;
	  if (now >= e->next_try)
	    ++n_current;
	}
      else if (e->active == REL_PMTUD_PROBE)
        {
          if (e->next_try != 0 && now >= e->next_try)
            {
                if (!plpmtud_lostprobe(&rel->pmtud_state, e->buf.len))
                  {
                    /* Discovery not done, can send another probe right away */
                    ++n_active;
                    ++n_current;
                  }
                else
                  reliable_update_mtu(rel, frame, plpmtud_get_pmtu(&rel->pmtud_state));
                buf_init (&e->buf, rel->offset);
                e->active = REL_ACKED;
            }
          else
            {
              ++n_active;
              if (now >= e->next_try)
                ++n_current;
            }
        }

      if (e->active == REL_ACKED)
        {
          if (plpmtud_can_send(&rel->pmtud_state))
            {
              /* a probe is not in queue now, but PMTUD wants and can send one
               * Tell the caller to not send anything else before this probe.
               * note: n_active counter will be off, it's only used for dmsg
               */
              n_current = 0;
              break;
            }
        }
    }
  dmsg (D_REL_DEBUG, "ACK reliable_can_send active=%d current=%d : %s",
       n_active,
       n_current,
       reliable_print_send_ids (rel, &gc));

  gc_free (&gc);
  return n_current > 0;
}

#ifdef EXPONENTIAL_BACKOFF
/* return a unique point-in-time to trigger retry */
static time_t
reliable_unique_retry (struct send_reliable *rel, time_t retry)
{
  int i;
  while (true)
    {
      for (i = 0; i < SIZE(rel->array); ++i)
	{
	  struct send_reliable_entry *e = &rel->array[i];
	  if (e->active >= REL_ACTIVE && e->next_try == retry)
	    goto again;
	}
      break;
    again:
      ++retry;
    }
  return retry;
}
#endif

/* return next buffer to send to remote */
struct buffer *
reliable_send (struct send_reliable *rel, int *opcode)
{
  int i;
  struct send_reliable_entry *best = NULL;
  const time_t local_now = now;

  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct send_reliable_entry *e = &rel->array[i];
      if (e->active >= REL_ACTIVE && local_now >= e->next_try)
	{
	  if (!best || reliable_pid_lt (e->packet_id, best->packet_id))
	    best = e;
	}
    }
  if (best)
    {
#ifdef EXPONENTIAL_BACKOFF
      /* exponential backoff */
      best->next_try = reliable_unique_retry (rel, local_now + best->timeout);
      best->timeout *= 2;
#else
      /* constant timeout, no backoff */
      best->next_try = local_now + best->timeout;
#endif
      *opcode = best->opcode;
      dmsg (D_REL_DEBUG, "ACK reliable_send ID " packet_id_format " (size=%d to=%d)",
	   (packet_id_print_type)best->packet_id, best->buf.len,
	   (int)(best->next_try - local_now));
      return &best->buf;
    }
  return NULL;
}

/* in how many seconds should we wake up to check for timeout */
/* if we return BIG_TIMEOUT, nothing to wait for */
interval_t
reliable_send_timeout (const struct send_reliable *rel)
{
  struct gc_arena gc = gc_new ();
  interval_t ret = BIG_TIMEOUT;
  int i;
  const time_t local_now = now;

  if (ret != BIG_TIMEOUT)
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      const struct send_reliable_entry *e = &rel->array[i];
      if (e->active >= REL_ACTIVE)
	{
	  if (e->next_try <= local_now)
	    {
	      ret = 0;
	      break;
	    }
	  else
	    {
	      ret = min_int (ret, e->next_try - local_now);
	    }
	}
    }

  dmsg (D_REL_DEBUG, "ACK reliable_send_timeout %d %s",
       (int) ret,
       reliable_print_send_ids (rel, &gc));

  gc_free (&gc);
  return ret;
}

/*
 * Enable an incoming buffer previously returned by a get function as active.
 */

void
reliable_mark_active_incoming (struct rec_reliable *rel, struct buffer *buf,
			       packet_id_type pid)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct rec_reliable_entry *e = &rel->array[i];
      if (buf == &e->buf)
	{
	  e->active = true;

	  /* packets may not arrive in sequential order */
	  e->packet_id = pid;

	  /* check for replay */
	  ASSERT (!reliable_pid_lt (pid, rel->packet_id));

	  dmsg (D_REL_DEBUG, "ACK mark active incoming ID " packet_id_format, (packet_id_print_type)e->packet_id);
	  return;
	}
    }
  ASSERT (0);			/* buf not found in rel */
}

/*
 * Enable an outgoing buffer previously returned by a get function as active.
 */

bool
reliable_mark_active_outgoing (struct send_reliable *rel, struct buffer *buf, int opcode, int activation, int overhead)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct send_reliable_entry *e = &rel->array[i];
      if (buf == &e->buf)
	{
          if (activation == REL_PMTUD_PROBE)
            {
              /* Look for a previously acked packet, and reuse it.
               * When probes get lost, there is no uncertainty about what
               * packet_id the peer expects next.
               */
              ASSERT (overhead != 0);
              if ( e->active == REL_ACKED && 
                  plpmtud_send_opportunity(&rel->pmtud_state, buf, overhead) )
                {
                  e->active = REL_PMTUD_PROBE;
                }
              else
                {
                    /* If this buffer was not previously acked, send it to be
                     * acked, so it can be used as probe in the future.
                     */
                    return false;
                }
            }
          else
            {
              /* Write mode, increment packet_id (i.e. sequence number)
                linearly and prepend id to packet */
              e->packet_id = rel->packet_id++;
              e->active = REL_ACTIVE;
            }
          packet_id_type net_pid;
          net_pid = htonpid (e->packet_id);
          ASSERT (buf_write_prepend (buf, &net_pid, sizeof (net_pid)));
          e->timeout = rel->initial_timeout;
          e->opcode = opcode;
	  e->next_try = 0;
          // e->sent_time = timeref;
	  dmsg (D_REL_DEBUG, "ACK mark active outgoing ID " packet_id_format "%s",
           (packet_id_print_type)e->packet_id,
            e->active == REL_PMTUD_PROBE ? " (PMTU probe)" : "");
	  return true;
	}
    }
  ASSERT (0);			/* buf not found in rel */
  return false;
}

/* delete a buffer previously activated by reliable_mark_active() */
void
reliable_mark_deleted (struct rec_reliable *rel, struct buffer *buf, bool inc_pid)
{
  int i;
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      struct rec_reliable_entry *e = &rel->array[i];
      if (buf == &e->buf)
	{
	  e->active = false;
	  if (inc_pid)
	    rel->packet_id = e->packet_id + 1;
	  return;
	}
    }
  ASSERT (0);
}

#if 0

void
reliable_ack_debug_print (const struct reliable_ack *ack, char *desc)
{
  int i;

  printf ("********* struct reliable_ack %s\n", desc);
  for (i = 0; i < ack->len; ++i)
    {
      printf ("  %d: " packet_id_format "\n", i, (packet_id_print_type) ack->packet_id[i]);
    }
}

void
reliable_debug_print (const struct send_reliable *rel, char *desc)
{
  int i;
  update_time ();

  printf ("********* struct reliable %s\n", desc);
  printf ("  initial_timeout=%d\n", (int)rel->initial_timeout);
  printf ("  packet_id=" packet_id_format "\n", rel->packet_id);
  printf ("  now=" time_format "\n", now);
  for (i = 0; i < SIZE(rel->array); ++i)
    {
      const struct send_reliable_entry *e = &rel->array[i];
      if (e->active)
	{
	  printf ("  %d: packet_id=" packet_id_format " len=%d", i, e->packet_id, e->buf.len);
	  printf (" next_try=" time_format, e->next_try);
	  printf ("\n");
	}
    }
}

#endif

#else
static void dummy(void) {}
#endif /* ENABLE_SSL*/
