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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include <getopt.h>
#include <math.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "rfc4821.h"
#include "buffer.h"

/* TODO: fuzz LINK_PACKETIZATION_THRESHOLD maybe
 */
struct buffer
alloc_buf (size_t size)
{
  struct buffer buf;
  CLEAR(buf);

  buf.capacity = (int) size;
  buf.offset = 0;
  buf.len = 0;
  buf.data = NULL; /* this test doesn't touch the data */

  return buf;
}

void
buf_realloc (struct buffer *b, int size)
{
  b->capacity = size + b->offset;
}

/* Reallocates the buffer to fit the len, then fills with
 * incompressible data.
 */
void
buf_fill_incompressible (struct buffer *b, uint16_t len)
{
  if (b->capacity - b->offset - b->len >= len)
    buf_realloc (b, b->offset + b->len + len);

  b->len = len;
}

static inline bool
my_buf_init (struct buffer *buf, int offset)
{
  if (offset < 0 || offset > buf->capacity)
    return false;
  buf->len = 0;
  buf->offset = offset;
  return true;
}

struct scenario
{

  struct
  {
    int interface_mtu;
    int start_mtu;
    int end_mtu;
    int mtu_increments;
    int packet_loss;
    int overhead;
    bool blackhole;
  } network;

  /* Connection */
  struct
  {
    int overhead;
    bool first_probe;
    unsigned int num_probe;
    struct buffer buf;
  } connection;

  /* peer */
  struct
  {
    int recv_buffer_size;
  } peer;
    
  struct plpmtud pmtud_state;
};

static int
setup (void **state)
{
  struct scenario *sc = calloc (sizeof (struct scenario), 1);
  *state = sc;

  sc->connection.first_probe = true;

  #define UDPv4_OVERHEAD 28
  sc->network.overhead = UDPv4_OVERHEAD;

  return 0;
}

static int
teardown (void **state)
{
  free (*state);
  return 0;
}

static void
connect_healthy_mtu_1500 (void **state)
{
  struct scenario *sc = *state;


  sc->network.start_mtu = 1500;
  sc->network.end_mtu = 1500;
  sc->network.mtu_increments = 1;
  sc->network.interface_mtu = 1500;

  msg (D_TEST_INFO, "Simulate a static network with interface MTU=%d PMTU=%d, steady state",
       sc->network.interface_mtu, sc->network.start_mtu);
}

static void
connect_slow_failing_mtu_1500 (void **state)
{
  struct scenario *sc = *state;


  sc->network.start_mtu = 1500;
  sc->network.end_mtu = 150;
  sc->network.mtu_increments = -1;
  sc->network.interface_mtu = 1500;

  msg (D_TEST_INFO, "Simulate a slowly failing network with interface MTU=%d PMTU=%d->%d (%d-byte steps)",
       sc->network.interface_mtu,
       sc->network.start_mtu,
       sc->network.end_mtu,
       sc->network.mtu_increments
       );
}

static void
connect_fast_failing_mtu_1500 (void **state)
{
  struct scenario *sc = *state;


  sc->network.start_mtu = 1500;
  sc->network.end_mtu = 60;
  sc->network.mtu_increments = -37;
  sc->network.interface_mtu = 1500;

  msg (D_TEST_INFO, "Simulate a quickly failing network with interface MTU=%d PMTU=%d->%d (%d-byte steps)",
       sc->network.interface_mtu,
       sc->network.start_mtu,
       sc->network.end_mtu,
       sc->network.mtu_increments
       );
}

static void
connect_mtu_1500_pmtu_1472 (void **state)
{
  struct scenario *sc = *state;

  sc->network.start_mtu = 1472;
  sc->network.end_mtu = 1472;
  sc->network.mtu_increments = 1;
  sc->network.interface_mtu = 1500;

  msg (D_TEST_INFO, "Simulate a static network with interface MTU=%d PMTU=%d, steady state",
       sc->network.interface_mtu, sc->network.start_mtu);
}

static void
connect_recovering_mtu_9000 (void **state)
{
  struct scenario *sc = *state;

  sc->network.start_mtu = 100;
  sc->network.end_mtu = 9000;
  sc->network.mtu_increments = 17;
  sc->network.interface_mtu = 0xffff;

  msg (D_TEST_INFO, "Simulate a network with PMTU increasing to %d over time (eg, bigger links coming"
       " online after a failure that made path MTU=%d)",
       sc->network.end_mtu, sc->network.start_mtu);
}

static void
connect_failing_mtu_9000 (void **state)
{
  struct scenario *sc = *state;

  sc->network.start_mtu = 9000;
  sc->network.end_mtu = 90;
  sc->network.mtu_increments = -91;
  sc->network.interface_mtu = 0xffff;

  msg (D_TEST_INFO, "Simulate a network with PMTU falling from %d to %d (%d-byte steps) over time "
       "(big links failing, network falling back on smaller links)",
       sc->network.start_mtu, sc->network.end_mtu, sc->network.mtu_increments);
}

static void
add_25pct_network_congestion (void **state)
{
  struct scenario *sc = *state;
  /* Every 4th sent packet will be discarded */
  sc->network.packet_loss = 4;
  msg (D_TEST_INFO, "Enable 25%% packet loss (congestion).");
}

static void
add_icmp_blackhole (void **state)
{
  struct scenario *sc = *state;
  sc->network.blackhole = true;
  msg (D_TEST_INFO, "Enable ICMP blackholes.");
}

/* Legacy peers will ack probes without checking their HMAC, so we must limit
 * probe size.
 * Default setting, recv_buffer_size == 0, means that the simulated peer
 * has this bug fixed (UNRELIABLE_RELIABLE quirk).
 * Non-zero values indicate an offset from the actual MTU. MTU+recv_buffer_size
 * is assumed to be the simulated peer's receive buffer size, thus the max
 * probe size it will reliably ACK.
 * For legacy peers, the test will also verify that the algo never probes with
 * a larger probe than the simulated receive buffer size.
 */
static void
simulate_legacy_peer_recv_buffer (void **state)
{
  struct scenario *sc = *state;

  int tun_mtu = 1300;
  #define LEGACY_EXTRA_BUFFER 41

  sc->peer.recv_buffer_size = 
          tun_mtu + LEGACY_EXTRA_BUFFER; /* emulate --tun-mtu=1300 on IPv4 UDP conn */

  msg (D_TEST_INFO, "Simulate legacy peer with --tun-mtu=%d on PROTO_UDPv4",
    sc->peer.recv_buffer_size - LEGACY_EXTRA_BUFFER);

  plpmtud_set_max_probe(&sc->pmtud_state, sc->peer.recv_buffer_size);

  if (sc->peer.recv_buffer_size)
    assert_true (sc->pmtud_state.max_probe == sc->peer.recv_buffer_size &&
      "before _start() operation with UNRELIABLE_RELIABLE peer acknowledged");

}


static void
begin_connection (void **state)
{
  struct scenario *sc = *state;
  struct plpmtud *s = &sc->pmtud_state;
  size_t initial_mtu = 1000;

#if !defined(NDEBUG)
  assert_true (!IS_INITIALIZED(s));
#endif

  plpmtud_init (s, initial_mtu);


  assert_true (s->active == PMTUD_DONE &&
               "_init() leaves search FSM in idle state");
  assert_true (s->pmtu == initial_mtu &&
               "_init() sets initial MTU estimate to first argument");
  assert_true (s->cursor == 0xffff &&
               "after _init() first probe will be a 65k probe");

  /* First check that random ACKs don't get the FSM started before _start() */
  my_expect_assert_failure (plpmtud_ack (s, 1000),
                            state->active == PMTUD_INFLIGHT,
                            "_ack() must throw if called before _start()");

  sc->connection.buf = alloc_buf (100);
}

static void
test_rfc4821_pmtu_discovery (void **state)
{
  struct scenario *sc = *state;
  struct plpmtud *s = &sc->pmtud_state;
  struct buffer *buf = &sc->connection.buf;

  size_t mtu;
  size_t mtu_est = 0;

  /* Each mtu loop simulates a different network condition.
   * A search is done for each condition, MTU is increased, and a new search
   * started to check that a reasonably close estimate is found.
   */
  for (mtu = sc->network.start_mtu;
          ( sc->network.start_mtu > sc->network.end_mtu && mtu >= sc->network.end_mtu) ||
          ( sc->network.start_mtu <= sc->network.end_mtu && mtu <= sc->network.end_mtu) ;
          mtu += sc->network.mtu_increments)
    {

      bool wants_to_send;

      assert_true (my_buf_init (buf, sc->network.overhead) &&
                   "Buffer initialization should not fail");

      wants_to_send = plpmtud_send_opportunity (s, buf, sc->network.overhead);

      assert_true (!wants_to_send &&
          "No probes transmitted before discovery is started");

      msg (D_TEST_DEBUG, "Begin discovery cycle for MTU=%d", mtu);

      plpmtud_start (s);
      assert_true (s->active == PMTUD_RESTING);

      my_expect_assert_failure (plpmtud_start (s),
                            state->active == PMTUD_DONE &&
                            "Discovery cannot be restarted while in progress",
                            "_start() must throw if already started");

      assert_true (s->active == PMTUD_RESTING);

      int pid;
      bool first_loss = true;
      int ack_num = 0;

      /* Each pid loop simulates one PMTU search
       */
      unsigned int last_cursor = s->cursor;
      unsigned int last_cursor_step = 0;
      size_t last_est;

      for (pid = 1, last_est = mtu_est;
              pid < 100 && s->active != PMTUD_DONE;
              pid++, last_est = mtu_est)
        {
          bp++;
          assert_true (my_buf_init (buf, sc->network.overhead) &&
                       "Buffer initialization should not fail");

          wants_to_send = plpmtud_send_opportunity (s, buf, sc->network.overhead);

          assert_true (wants_to_send &&
                "Should send probes when PMTUD_RESTING");
          assert_true ( (sc->peer.recv_buffer_size == 0 /* new client */ ||
                  buf->len + sc->network.overhead <= sc->peer.recv_buffer_size /* legacy */) && 
                  "Limit probe size to legacy peer");

          assert_true (buf->len == s->cursor - sc->network.overhead &&
                       "probing opportunities must be sized equal to the search cursor");
          assert_true (s->active == PMTUD_INFLIGHT &&
                       "after _send_opportunity() sends a probe, FSM must be INFLIGHT");

          sc->connection.num_probe++;
          if (pid == 1)
            {
              assert_true (buf->len + sc->network.overhead == 
                            (sc->peer.recv_buffer_size ? sc->peer.recv_buffer_size : 0xffff ) &&
                           s->active == PMTUD_INFLIGHT &&
                           "first probe is large to discover interface MTU");
              sc->connection.first_probe = false;
            }

          if (buf->len + sc->network.overhead > sc->network.interface_mtu)
            {
              plpmtud_hint (s, sc->network.interface_mtu);
              /* _hint() should only be needed on the first packet after _start()
               */
              assert_true ((pid == 1 || pid != 2 || s->active == PMTUD_DONE || first_loss) &&
                           "_send_opportunity() should not send packets larger than hinted MTU, right after hint");

              mtu_est = plpmtud_get_pmtu(s);
              first_loss = false;
              /* Integration Note:
               * When a probe is rejected with EMSGSIZE, _hint should be called
               * with the socket's reported MTU size, and the timeout for the
               * corresponding probe cancelled. That probe was lost.
               * The application can immediately _send_opportunity() the next
               * probe if s->active != _DONE. If _DONE, the pmtu estimate is also
               * updated and buffers should be sized down.
               * Otherwise, the search will continue, waste time and CPU cycles
               * but the end result should be the same. This would be a performance
               * bug rather than a breaking bug.
               */
              continue; /* Ie, next send_opportunity(), no waiting for timeout or ack */
            }
          else if (!sc->network.blackhole && buf->len + sc->network.overhead > mtu)
            {
              plpmtud_hint (s, mtu);
              mtu_est = plpmtud_get_pmtu(s);
              first_loss = false;
              continue;
            }
          if (buf->len + sc->network.overhead > mtu ||
              ( sc->network.packet_loss && sc->connection.num_probe % sc->network.packet_loss == 1) )
            {
              if (plpmtud_lostprobe (s, buf->len + sc->network.overhead))
                {
                  /* DONE. App should set buffers according to new MTU estimate
                   */
                  mtu_est = plpmtud_get_pmtu(s);
                }
              first_loss = false;
              if (sc->network.packet_loss == 0)
                  assert_true ( (
                      ack_num <= 1 ||
                      s->active == PMTUD_DONE ||
                      abs(s->cursor - last_cursor) < last_cursor_step ||
                      s->cursor > last_cursor ||
                      s->upper_bound - s->pmtu <= 2) &&
                    "_lostprobe() converges");
              if (s->active == PMTUD_DONE)
                msg (D_TEST_DEBUG, "#%2u %5u Lost. Done. Final estimated PMTU=%u Actual PMTU=%u", pid, buf->len + sc->network.overhead, mtu_est, mtu);
              else
                msg (D_TEST_DEBUG, "#%2u %5u Lost. Next: %u", pid, buf->len + sc->network.overhead, s->cursor);
              
              assert_true ( (s->active == PMTUD_DONE || s->cursor < s->max_probe) &&
                    "Should not send max probe after 1st probe"
                 );
            }
          else
            {
              mtu_est = plpmtud_ack (s, buf->len + sc->network.overhead);
              if (s->active == PMTUD_DONE)
                msg (D_TEST_DEBUG, "#%2u %5u Ack. Done. Final PMTU=%u Actual PMTU=%u", pid, buf->len + sc->network.overhead, mtu_est, mtu);
              else
                msg (D_TEST_DEBUG, "#%2u %5u Ack.  Next: %u", pid, buf->len + sc->network.overhead, s->cursor);
              assert_true (mtu_est != 0);
              if (sc->network.packet_loss == 0)
                {
                    assert_true ( (ack_num == 0 || mtu_est >= last_est) &&
                      "MTU estimate should not decrease after ACK");
                    assert_true ( (
                      ack_num == 0 ||
                      s->active == PMTUD_DONE ||
                      abs(s->cursor - last_cursor) < last_cursor_step ||
                      (abs(s->cursor - last_cursor) == last_cursor_step && s->cursor != last_cursor)
                      ) &&
                      "_ack() converges");
                }

              assert_true (plpmtud_get_pmtu (s) == mtu_est &&
                "_get_pmtu() returns the same value as _ack()");
              ack_num++;
            }

          last_cursor_step = abs(s->cursor - last_cursor);
          last_cursor = s->cursor;

          assert_true ((sc->network.packet_loss || s->active == PMTUD_DONE || ack_num == 0 || s->cursor >= mtu_est) &&
                       "search should not backtrack w/o packet loss");

          assert_true ((s->active != PMTUD_DONE || mtu_est != 0) &&
                       "don't stop searching until a possible MTU is found");

        }
      /* At most twice the log2(i/f MTU) steps will be taken.
       * The worst case is when a network with high MTU (65K) that has been
       * completely (_DONE) estimated, suddenly drops to the smallest PMTU (100)
       * The estimator cannot distinguish a small-mtu scenario from a
       * disconnected scenario, so it searches all the way down to 100, then
       * (as if a reconnect occurred before the 100B probe), searches back
       * up to interface MTU to estimate PMTU post reconnect.
       */
      assert_true (pid <= 2 * log2 (sc->network.interface_mtu - LINK_PACKETIZATION_THRESHOLD) + 3 &&
            "search complexity should be max O(log2(n))");
      
      if (mtu <= LINK_PACKETIZATION_THRESHOLD)
        {
          /* For tiny links, it's not worth packetizing, the overhead is too high
           * Give the threshold as the estimate, and let the OS fragment the
           * link traffic.
           */
          assert_true (mtu_est == LINK_PACKETIZATION_THRESHOLD &&
                "Links under the PACKETIZATION_THRESHOLD are MTU given the threshold as estimate");
        }
      else
        {
          /* Larger links (PMTU > LINK_PACKETIZATION_THRESHOLD), give the correct
           * estimate, so the application will packetize and OS fragmentation
           * is avoided.
           */
          if (!sc->network.packet_loss)
            assert_true (mtu_est == mtu &&
                "discovery ends with the correct MTU estimate");
          else
            assert_true (mtu_est <= mtu &&
                "discovery ends with a MTU estimate (not optimal due to probe loss, but not wrong)");

          assert_true (mtu_est == s->pmtu &&
              "when _DONE, reported PMTU estimate must be same as tracked PMTU");
        }


    }
}

unsigned int verb = 0;
unsigned int bp = 0;

static void
do_getopt (int argc, char **argv)
{
  int c;
  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"verb", optional_argument, 0, 'v'},
        {0, 0, 0, 0}
      };

      c = getopt_long (argc, argv, "v::",
                       long_options, &option_index);
      if (c == -1)
        break;

      switch (c)
        {

        case 'v': if (optarg)
            verb = atoi (optarg);
          else
            verb++;
          break;
        case '?':
          exit (1);
          break;

        default:
          printf ("?? getopt returned character code 0%o ??\n", c);
        }
    }
}

int
main (int argc, char **argv)
{
  const struct CMUnitTest healthy_networks[] = {
    cmocka_unit_test (begin_connection),
    cmocka_unit_test (connect_recovering_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_recovering_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_mtu_1500_pmtu_1472),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
  };

  const struct CMUnitTest blackhole_networks[] = {
    cmocka_unit_test (begin_connection),
    cmocka_unit_test (add_icmp_blackhole),
    cmocka_unit_test (connect_recovering_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_recovering_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_mtu_1500_pmtu_1472),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
  };

  const struct CMUnitTest disrupted_blackhole_networks[] = {
    cmocka_unit_test (begin_connection),
    cmocka_unit_test (add_icmp_blackhole),
    cmocka_unit_test (connect_failing_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_failing_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_fast_failing_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_slow_failing_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_mtu_1500_pmtu_1472),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
  };

  const struct CMUnitTest disrupted_congested_blackhole_networks[] = {
    cmocka_unit_test (begin_connection),
    cmocka_unit_test (add_icmp_blackhole),
    cmocka_unit_test (add_25pct_network_congestion),
    cmocka_unit_test (connect_failing_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_failing_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_fast_failing_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_slow_failing_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_mtu_1500_pmtu_1472),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
  };

  const struct CMUnitTest disrupted_congested_blackhole_networks_legacy_peer[] = {
    cmocka_unit_test (begin_connection),
    cmocka_unit_test (add_icmp_blackhole),
    cmocka_unit_test (add_25pct_network_congestion),
    cmocka_unit_test (simulate_legacy_peer_recv_buffer),
    cmocka_unit_test (connect_failing_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_failing_mtu_9000),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_fast_failing_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_healthy_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_slow_failing_mtu_1500),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
    cmocka_unit_test (connect_mtu_1500_pmtu_1472),
    cmocka_unit_test (test_rfc4821_pmtu_discovery),
  };

  do_getopt (argc, argv);

  int result = cmocka_run_group_tests_name ("healthy_networks", healthy_networks, setup, teardown)
       || cmocka_run_group_tests_name ("blackhole_networks", blackhole_networks, setup, teardown)
       || cmocka_run_group_tests_name ("disrupted_blackhole_networks", disrupted_blackhole_networks, setup, teardown)
       || cmocka_run_group_tests_name ("disrupted_congested_blackhole_networks", disrupted_congested_blackhole_networks, setup, teardown)
       || cmocka_run_group_tests_name ("disrupted_congested_blackhole_networks_legacy_peer", disrupted_congested_blackhole_networks_legacy_peer, setup, teardown)
       ;

  if (result == 255) /* Cmocka error, failed to test */
    return AUTOMAKE_TEST_HARD_ERROR;
  
  return !!result;
}
