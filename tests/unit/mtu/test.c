#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <getopt.h>
#include <inttypes.h>

#include "syshead.h"

#include "mtu.h"
#include "options.h" /* For OPT_P_PEER_ID */

#include "ssl.h" /* for P_OPCODE_*_LEN */

#if defined(PA_BRACKET)
/* In 2.1, at bda8d3, buf_printf was changed from returning void to bool
 * Use PA_BRACKET which was defined in buffer.h before this change to detect
 * which flavour is declared in buffer.h
 */
bool
buf_printf (struct buffer *buf, const char *format, ...)
#else
void
buf_printf (struct buffer *buf, const char *format, ...)
#endif
{
#if defined(PA_BRACKET)
  int ret = false;
#endif
  if (buf_defined (buf))
    {
      va_list arglist;
      uint8_t *ptr = BEND (buf);
      int cap = buf_forward_capacity (buf);

      if (cap > 0)
	{
	  int stat;
	  va_start (arglist, format);
	  stat = vsnprintf ((char *)ptr, cap, format, arglist);
	  va_end (arglist);
	  *(buf->data + buf->capacity - 1) = 0; /* windows vsnprintf needs this */
	  buf->len += (int) strlen ((char *)ptr);
#if defined(PA_BRACKET)
	  if (stat >= 0 && stat < cap)
	    ret = true;
#endif
	}
    }
#if defined(PA_BRACKET)
  return ret;
#endif
}

#include "socket.h"

const int proto_overhead[] = { /* indexed by PROTO_x */
  IPv4_UDP_HEADER_SIZE,
  IPv4_TCP_HEADER_SIZE,
  IPv6_UDP_HEADER_SIZE,
#if defined(IPv6_TCP_HEADER_SIZE)
  IPv6_TCP_HEADER_SIZE,
#endif
};
#define my_proto_overhead proto_overhead

static const char *
proto_name_str(int proto)
{
  switch (proto)
    {
      case 0: return "UDPv4";
      case 1: return "TCPv4";
      case 2: return "UDPv6";
      case 3: return "TCPv6";
    }
  return "OTHER";
}

/* Pre backwards compatibility adjustments.
 * These tests target source code quality rather than functionality.
 * They are only enabled for maintainers, because there is nothing a packager
 * needs to do about the quality of the source.
 */
#if defined(IMPLEMENTATION_mtu2)
/* Static analysis.
 * 
 * This test only validates that the expected pre-processor macros exist when
 * they should, and more importantly, that they are not defined when they are
 * not needed (this would be a trap waiting for a future developer).
 * If a definition exists unexpectedly, it creates the hazard of being used
 * somewhere where it should not be used. Eg, if SID_SIZE is used when
 * ENABLE_SSL is not defined, somewhere, something has a bug, because SID is
 * meaningless in non-SSL builds.
 */
static void test_static_analysis(void **state)
{
/* If macros are defined needlessly, it may tempt their use, which would be
 * invalid.
 */
#if defined(ENABLE_SSL)
#if !defined(SID_SIZE)
  assert_false ("SID_SIZE should be defined when ENABLE_SSL is defined");
#else
  assert_true ("SID_SIZE is defined");
#endif
#if !defined(ACK_SIZE)
  assert_false ("ACK_SIZE should be defined when ENABLE_SSL is defined");
#else
  assert_true ("ACK_SIZE is defined");
#endif
#if !defined(OPT_P_PEER_ID)
#if defined(P_OPCODE_CONTROL_LEN)
  assert_false ("P_OPCODE_CONTROL_LEN should only be defined when OPT_PEER_ID is defined");
#else
  assert_true ("P_OPCODE_CONTROL_LEN is not defined");
#endif
#if defined(P_OPCODE_DATA_V1_LEN)
  assert_false ("P_OPCODE_DATA_V1_LEN should only be defined when OPT_PEER_ID is defined");
#else
  assert_true ("P_OPCODE_DATA_V1_LEN is not defined");
#endif
#if defined(P_OPCODE_DATA_V2_LEN)
  assert_false ("P_OPCODE_DATA_V2_LEN should only be defined when OPT_PEER_ID is defined");
#else
  assert_true ("P_OPCODE_DATA_V2_LEN is not defined");
#endif
#if !defined(P_OPCODE_LEN)
  assert_false ("P_OPCODE_LEN should be defined when OPT_PEER_ID is not defined");
#else
  assert_true ("P_OPCODE_LEN is defined");
#endif
#else /* OPT_P_PEER_ID */
#if !defined(P_OPCODE_DATA_V1_LEN)
  assert_false ("P_OPCODE_DATA_V1_LEN should be defined when OPT_PEER_ID is defined");
#else
  assert_true ("P_OPCODE_DATA_V1_LEN is defined");
#endif
#if !defined(P_OPCODE_DATA_V2_LEN)
  assert_false ("P_OPCODE_DATA_V2_LEN should be defined when OPT_PEER_ID is defined");
#else
  assert_true ("P_OPCODE_DATA_V2_LEN is defined");
#endif
#if defined(P_OPCODE_LEN)
  assert_false ("P_OPCODE_LEN should not be defined when OPT_PEER_ID is defined");
#else
  assert_true ("P_OPCODE_LEN is not defined");
#endif
#endif

#else /* ENABLE_SSL */
#if defined(SID_SIZE)
  assert_false ("SID_SIZE should only be defined when ENABLE_SSL is defined");
#else
  assert_true ("SID_SIZE is not defined");
#endif
#if defined(ACK_SIZE)
  assert_false ("ACK_SIZE should only be defined when ENABLE_SSL is defined");
#else
  assert_true ("ACK_SIZE is not defined");
#endif
#if defined(OPT_P_PEER_ID)
  assert_false ("OPT_P_PEER_ID should only be defined when ENABLE_SSL is defined");
#else
  assert_true ("OPT_P_PEER_ID is not defined");
#endif
#endif

}
#endif
#if defined(IMPLEMENTATION_2_4)
/* At 2.4, a new function was added:
 * frame_init_mssfix(struct frame *frame, const struct options *options)
 */
#endif

#if defined(IMPLEMENTATION_2_0) || defined(IMPLEMENTATION_2_4)
static void test_static_analysis(void **state)
{
#if !defined(BUF_SIZE)
  assert_false ("BUF_SIZE should be defined");
#else
  assert_true ("BUF_SIZE is defined");
#endif
#if !defined(MAX_RW_SIZE_TUN)
  assert_false ("MAX_RW_SIZE_TUN should be defined");
#else
  assert_true ("MAX_RW_SIZE_TUN is defined");
#endif
#if !defined(EXPANDED_SIZE)
  assert_false ("EXPANDED_SIZE should be defined");
#else
  assert_true ("EXPANDED_SIZE is defined");
#endif
}
#endif

/* Backwards compatibility tweaks (#if .. #elif ladder in descending order)
 * Allow some new tests to run against obsoleted interfaces.
 * Ie, how to run 2.new tests on 2.old libraries?
 */
#if defined(IMPLEMENTATION_mtu2)
    #if defined(ENABLE_SSL)
    #if defined(OPT_P_PEER_ID)
    /* a new P_DATA_V2 4-byte opcode was added at 0e1fd33*/
    #define P_OPCODE_DATA_LEN (s->inputs.use_peer_id ? P_OPCODE_DATA_V2_LEN : P_OPCODE_DATA_V1_LEN)
    #else
    #define P_OPCODE_DATA_LEN P_OPCODE_LEN
    #define P_OPCODE_CONTROL_LEN P_OPCODE_LEN
    #endif
    #endif
#elif defined(IMPLEMENTATION_2_4)
/* At 2.4, a new function was added:
 * frame_init_mssfix(struct frame *frame, const struct options *options)
 */
#elif defined(IMPLEMENTATION_2_0)
#endif

/* Forward compatibility tweaks (#if .. #elif ladder in ascending order)
 * Later revision implementations normally assume all lower revisions are still
 * implemented, ie, new functions are added, but not removed.
 * If in some future branch, 2_0 is completely removed, the new assumption
 * in that branch will be that the API is 2.2, while all the other branches
 * can still use the 2.0 API.
 *
 * Instead of thinking about fwd compatibility, it may be easier to update the
 * test to the latest version, and update the backward-compatibility tweak
 * section.
 */
#if defined(IMPLEMENTATION_2_0)
/* How to test the equivalent of frame_init_mssfix?
 */
#elif defined(IMPLEMENTATION_2_4)
#elif defined(IMPLEMENTATION_mtu2)
#endif


uint8_t print_buffer[1024];

struct buffer
alloc_buf_gc (size_t size, struct gc_arena *gc)
{
  struct buffer buf;
  CLEAR(buf);

  ASSERT (sizeof(print_buffer) >= size && "print buffer is large enough");

  buf.capacity = (int)size;
  buf.offset = 0;
  buf.len = 0;
  buf.data = print_buffer;

  /* Will be called when frame_init_* is called, to log the updated params, 
   if verb */
  assert_true (verb >= D_MTU_INFO && 
       "Only allocate memory at frame init, if verbosity is >= D_MTU_INFO");

  return buf;
}

struct buffer
alloc_buf (size_t size)
{
  struct buffer buf;
  CLEAR(buf);

  buf.capacity = (int)size;
  buf.offset = 0;
  buf.len = 0;

  buf.data = NULL;

  assert_false (!!"Unexpected call to alloc_buf()");

  return buf;
}

void
x_gc_free (struct gc_arena *a)
{
}

void *
#ifdef DMALLOC
gc_malloc_debug (size_t size, bool clear, struct gc_arena *a, const char *file, int line)
#else
gc_malloc (size_t size, bool clear, struct gc_arena *a)
#endif
{
  assert_false (!!"Unexpected call to gc_malloc()");
  return print_buffer;
}
void
buf_rmtail (struct buffer *buf, uint8_t remove)
{
  assert_false (!!"Unexpected call to buf_rmtail()");
}

struct mystate {
  struct frame frame;
  struct inputs {
    bool      discovered_pmtu;
    uint16_t  PMTU;
    uint16_t  TLS_AUTH_SIZE;
    int       PROTO;

    int       num_acks;
    uint16_t  link_headroom; /* Socks wrapper */

#if defined (OPT_P_PEER_ID)
    bool     use_peer_id;
#endif
#if defined(ENABLE_LZO)
    uint16_t lzo_headroom;
#endif
#if defined(ENABLE_FRAGMENT)
    uint16_t fragment_headroom;
#endif
    uint16_t headroom;
    uint16_t overhead;
    uint16_t alignment;
  } inputs;
};
#if defined(ENABLE_LZO)
#define LZO_HEADROOM (s->inputs.lzo_headroom)
#else
#define LZO_HEADROOM (0)
#endif

#if defined(ENABLE_FRAGMENT)
#define FRAGMENT_HEADROOM (s->inputs.fragment_headroom)
#else
#define FRAGMENT_HEADROOM (0)
#endif

static void fuzzit (struct mystate *s)
{
    bp++;
    s->inputs.discovered_pmtu = rand() & 1;
    if (s->inputs.discovered_pmtu)
      s->inputs.PMTU = 300 + (rand() % 10) * 211;
    else
#if defined(LINK_MTU_STARTUP)
      s->inputs.PMTU = LINK_MTU_STARTUP;
#else
      s->inputs.PMTU = LINK_MTU_DEFAULT;
#endif

    s->inputs.TLS_AUTH_SIZE = rand() % 42;
    s->inputs.PROTO = rand() % SIZE(my_proto_overhead);

    s->inputs.num_acks = rand() % 2;
    s->inputs.link_headroom = (rand() %2) * 10; /* socks5 headroom */
#if defined (OPT_P_PEER_ID)
    s->inputs.use_peer_id = !!(rand() %2);
#endif
#if defined(ENABLE_LZO)
    s->inputs.lzo_headroom = rand() % 2;
#endif
#if defined(ENABLE_FRAGMENT)
    s->inputs.fragment_headroom = (rand() % 2) * 4;
#endif
    s->inputs.headroom = (rand() % 10) * 4;
    s->inputs.overhead = (rand() % 10) * 4 + s->inputs.headroom;
    /* Make alignments multiple of 4, but throw in some weird ones half the time
     * to catch alignment calulations by mask instead of modulo.
     */
    s->inputs.alignment = (rand() % 5) * 4 + (rand() % 2);
}

void
show_inputs(struct inputs *inputs)
{
    msg (D_TEST_INFO, "Inputs: PMTU=%"PRIu16" (%s) TLS_AUTH_SIZE=%"PRIu16" PROTO=%s(%"PRIu16"-byte header) LINK_h/r=%"PRIu16
#if defined (OPT_P_PEER_ID)
            " Data_v2=%d"
#endif

#if defined(ENABLE_LZO)
            " LZO_o/h=%"PRIu16
#endif
#if defined(ENABLE_FRAGMENT)
            " FRAG_o/h=%"PRIu16
#endif
            " CRYPTO: headroom=%"PRIu16" overhead=%"PRIu16" align=%"PRIu16,

            inputs->PMTU,
            inputs->discovered_pmtu ? "discovered" : "default",

            inputs->TLS_AUTH_SIZE,
            proto_name_str(inputs->PROTO),
            my_proto_overhead[inputs->PROTO],
            inputs->link_headroom,
#if defined (OPT_P_PEER_ID)
            inputs->use_peer_id,
#endif
#if defined(ENABLE_LZO)
            inputs->lzo_headroom,
#endif
#if defined(ENABLE_FRAGMENT)
            inputs->fragment_headroom,
#endif
            inputs->headroom,
            inputs->overhead,
            inputs->alignment
            );
}

static int setup_fuzz(void **state) {
     *state  = calloc(1, sizeof(struct mystate));
     fuzzit(*state);
     return (*state == NULL);
}

static int setup_typical(void **state) {
     *state  = calloc(1, sizeof(struct mystate));
     struct mystate *s = *state;
     struct inputs inputs = {
        .discovered_pmtu    = false,
#if defined(LINK_MTU_STARTUP)
        .PMTU               = LINK_MTU_STARTUP,
#else
        .PMTU               = LINK_MTU_DEFAULT,
#endif
        .TLS_AUTH_SIZE      = 20,
        .PROTO              = 0,
        .link_headroom      = 0,
        .num_acks           = 1,
#if defined(ENABLE_LZO)
        .lzo_headroom       = 1,
#endif
#if defined(ENABLE_FRAGMENT)
        .fragment_headroom  = 4,
#endif
        .headroom           = 16,
        .overhead           = 16,
        .alignment          = 8,
#if defined (OPT_P_PEER_ID)
        .use_peer_id        = false,
#endif
     };
     s->inputs = inputs;
     return (*state == NULL);
}

static int teardown(void **state) {
  struct mystate *c = *state;

  free(c);
  return 0;
}

#if defined(IMPLEMENTATION_mtu2)
static void test_init(void **state)
{
  struct mystate *s = *state;

  show_inputs(&s->inputs);
  assert_true ( s->inputs.overhead >= s->inputs.headroom &&
         "The overhead includes headroom");


  my_expect_assert_failure (frame_get_data_headroom (&s->frame),
                            IS_INITIALIZED(&frame->config),
                            "data param getter _headroom() must throw if called before _init_config()");

  frame_init_config (&s->frame,
                    s->inputs.TLS_AUTH_SIZE,
                    s->inputs.link_headroom);

  my_expect_assert_failure (frame_get_data_headroom (&s->frame),
                            IS_INITIALIZED(&frame->config.crypto),
                            "data param getter _headroom() must throw if called before _init_crypto()");

  frame_init_crypto (&s->frame,
#if defined(ENABLE_LZO)
            s->inputs.lzo_headroom,
#endif
#if defined(ENABLE_FRAGMENT)
            s->inputs.fragment_headroom,
#endif
            s->inputs.headroom,
            s->inputs.overhead,
            s->inputs.alignment
    );

#if defined(OPT_P_PEER_ID)
  my_expect_assert_failure (frame_get_data_headroom (&s->frame),
                            IS_INITIALIZED(&frame->config.crypto.pulled_opts),
                            "data param getter _headroom() must throw if called before _init_pulled_opts()");

  frame_init_pulled_opts (&s->frame,
                          s->inputs.use_peer_id);
#endif

  assert_int_equal (frame_get_data_headroom (&s->frame),
                    s->inputs.link_headroom +
#if defined(ENABLE_SSL)
                    P_OPCODE_DATA_LEN +
#endif
                    s->inputs.headroom
                    );


  my_expect_assert_failure (frame_get_link_pmtu (&s->frame),
                            IS_INITIALIZED(&frame->link),
                            "link param getter _pmtu() must throw if called before _init_link()");

  frame_init_link (&s->frame,
                    s->inputs.PROTO);

  assert_true (frame_get_link_pmtu (&s->frame) == LINK_MTU_STARTUP);


#if defined(LINK_MSS)
  assert_int_equal (LINK_RECV_BUFSIZE_STARTUP(&s->frame), LINK_MSS + LINK_MSS_GUARD);
#else
  assert_int_equal (LINK_RECV_BUFSIZE_STARTUP(&s->frame), (IP_MAXPACKET - 28));
#endif

  assert_int_equal (TUN_RECV_BUFSIZE_STARTUP, TUN_MTU_DEFAULT + TUN_MSDU_GUARD);

}

static void test_link_ssl_encapsulations(void **state)
{
  struct mystate *s = *state;

  assert_true (frame_get_link_encapsulation (&s->frame) == my_proto_overhead[s->inputs.PROTO]);

#if defined(ENABLE_SSL) && defined(ENABLE_CRYPTO)
  assert_int_equal (frame_get_reliable_encapsulation (&s->frame, s->inputs.num_acks),
                    my_proto_overhead[s->inputs.PROTO] +
                    s->inputs.link_headroom +
                    P_OPCODE_CONTROL_LEN +
                    SID_SIZE +
                    ACK_SIZE(s->inputs.num_acks)
              );

  assert_true (frame_get_control_encapsulation (&s->frame, s->inputs.num_acks) ==
                    my_proto_overhead[s->inputs.PROTO] +
                    s->inputs.link_headroom +
                    P_OPCODE_CONTROL_LEN +
                    SID_SIZE +
                    ACK_SIZE(s->inputs.num_acks) +
                    s->inputs.TLS_AUTH_SIZE +
                    sizeof(packet_id_type)
              );
#endif
  
}

static void test_link_crypto_encapsulations(void **state)
{
  struct mystate *s = *state;

  assert_true (frame_get_link_encapsulation (&s->frame) == my_proto_overhead[s->inputs.PROTO]);

  assert_true (frame_get_data_comp_encapsulation (&s->frame) ==
                    my_proto_overhead[s->inputs.PROTO] +
                    s->inputs.link_headroom +
#if defined(ENABLE_SSL)
                    P_OPCODE_DATA_LEN +
#endif
                    LZO_HEADROOM +
                    FRAGMENT_HEADROOM +
                    s->inputs.headroom
              );
  
}

static void test_bufsize_calculations(void **state)
{
  struct mystate *s = *state;

  if (s->inputs.discovered_pmtu)
    {
        frame_set_mtu (&s->frame, s->inputs.PMTU);
        frame_print (&s->frame, D_TEST_INFO, "PMTU Updated:");

    }

  /* Socket send buffer */
  assert_int_equal (frame_get_link_bufsize (&s->frame),
                    s->inputs.PMTU -
                    my_proto_overhead[s->inputs.PROTO]
                    );

#if defined(ENABLE_SSL) && defined(ENABLE_CRYPTO)
  assert_int_equal (frame_get_control_payload_room (&s->frame, s->inputs.num_acks),
                    s->inputs.PMTU -
                    my_proto_overhead[s->inputs.PROTO] -
                    s->inputs.link_headroom -
                    P_OPCODE_CONTROL_LEN -
                    SID_SIZE -
                    ACK_SIZE(s->inputs.num_acks) -
                    s->inputs.TLS_AUTH_SIZE -
                    sizeof(packet_id_type)
              );
#endif

  int payload_pre_padding =
                    s->inputs.PMTU -
                    my_proto_overhead[s->inputs.PROTO] -
                    s->inputs.link_headroom -
#if defined(ENABLE_SSL)
                    P_OPCODE_DATA_LEN -
#endif  
                    s->inputs.overhead;

  msg (D_TEST_DEBUG, "payload_pre_padding %d bytes", payload_pre_padding);
  assert_true (payload_pre_padding > 0);
  uint16_t room;
  if (s->inputs.alignment > 0)
    {
      room = payload_pre_padding -  payload_pre_padding % s->inputs.alignment - 1;
      assert_true ( (payload_pre_padding <= s->inputs.alignment - 1 ||
                    room % s->inputs.alignment == s->inputs.alignment -1) &&
              "Max room occurs with minimum padding of 1 byte");
    }
  else
    {
      room = payload_pre_padding;
    }

#if defined(ENABLE_FRAGMENT)
    room -= FRAGMENT_HEADROOM;

  assert_int_equal (frame_get_data_frag_payload_room (&s->frame), room);
#endif
    
    room -= LZO_HEADROOM;

  msg (D_TEST_DEBUG, "Expected uncompressed data room: %d bytes. mtu.c expects %d", room, frame_get_data_comp_payload_room (&s->frame));
  assert_int_equal (frame_get_data_comp_payload_room (&s->frame), room);
  
  
}

static void test_headroom_calculations(void **state)
{
  struct mystate *s = *state;

#if defined(ENABLE_SSL)
  assert_int_equal (frame_get_control_headroom (&s->frame, s->inputs.num_acks),
                    s->inputs.link_headroom +
                    P_OPCODE_CONTROL_LEN +
                    SID_SIZE +
                    ACK_SIZE(s->inputs.num_acks) +
                    s->inputs.TLS_AUTH_SIZE +
                    sizeof(packet_id_type)
              );

  assert_int_equal (frame_get_reliable_headroom (&s->frame, s->inputs.num_acks),
                    s->inputs.link_headroom +
                    P_OPCODE_CONTROL_LEN +
                    SID_SIZE +
                    ACK_SIZE(s->inputs.num_acks)
              );
#endif

  /* Headroom needed for data compressed and fragmented buffers, in order to
   * encrypt them.
   */
  assert_int_equal (frame_get_data_headroom (&s->frame),
                    s->inputs.link_headroom +
#if defined(ENABLE_SSL)
                    P_OPCODE_DATA_LEN +
#endif
                    s->inputs.headroom
                    );

  /* Headroom needed for uncompressed data, in order to compress, fragment, and
   * encrypt.
   */
  assert_int_equal (frame_get_data_comp_headroom (&s->frame),
                    s->inputs.link_headroom +
#if defined(ENABLE_SSL)
                    P_OPCODE_DATA_LEN +
#endif
                    LZO_HEADROOM +
                    FRAGMENT_HEADROOM +
                    s->inputs.headroom
                    );


#if defined(ENABLE_FRAGMENT)
  /* Headroom needed for compressed data, in order to fragment, and
   * encrypt.
   */
  assert_int_equal (frame_get_data_frag_headroom (&s->frame),
                    s->inputs.link_headroom +
#if defined(ENABLE_SSL)
                    P_OPCODE_DATA_LEN +
#endif
                    s->inputs.fragment_headroom +
                    s->inputs.headroom
                    );
#endif
}

static void test_overhead_calculations(void **state)
{
  struct mystate *s = *state;

  uint16_t len;
  for (len = 1000 ; len < 1070 ; len++) {

    uint16_t fragmented;

    fragmented =  len +
            LZO_HEADROOM +
            FRAGMENT_HEADROOM +
            0;

    assert_int_equal (frame_get_data_padding(&s->frame, fragmented),
                      s->inputs.alignment ? 
                        (s->inputs.alignment - 
                          (fragmented + s->inputs.overhead - s->inputs.headroom) %s->inputs.alignment) : 
                        0);
      
    msg (D_TEST_DEBUG, "data=%"PRIu16" expect_data_overhead=%"PRIu16" got=%"PRIu16, len,
                        s->inputs.overhead +
                        frame_get_data_padding(&s->frame, fragmented) +
                        s->inputs.link_headroom,
#if defined(ENABLE_SSL)
                        P_OPCODE_DATA_LEN +
#endif
                        frame_get_data_overhead (&s->frame, fragmented)
         );

    assert_int_equal (frame_get_data_overhead (&s->frame, fragmented),
                        s->inputs.overhead +
                        frame_get_data_padding(&s->frame, fragmented) +
#if defined(ENABLE_SSL)
                        P_OPCODE_DATA_LEN +
#endif
                        s->inputs.link_headroom);

    msg (D_TEST_DEBUG, "data=%"PRIu16" expect_data_comp_overhead=%"PRIu16" got=%"PRIu16"", len,
                        fragmented - len + /* compression + fragmentation */
                        s->inputs.overhead +
                        frame_get_data_padding(&s->frame, fragmented) +
#if defined(ENABLE_SSL)
                        P_OPCODE_DATA_LEN +
#endif
                        s->inputs.link_headroom,
                        frame_get_data_comp_overhead (&s->frame, len)
         );

    assert_int_equal (frame_get_data_comp_overhead (&s->frame, len),
                        fragmented - len + /* compression + fragmentation */
                        s->inputs.overhead +
                        frame_get_data_padding(&s->frame, fragmented) +
#if defined(ENABLE_SSL)
                        P_OPCODE_DATA_LEN +
#endif
                        s->inputs.link_headroom);
    }

}
#endif


unsigned int verb = 0;

/* Convenience breakpoint variable. Set a conditional breakpoint on any line
 * in your debugger, on the condition that bp=={number}
 * In verbose mode, messages print the value of bp at the time they were called.
 * you can increment or change it anywhere state changes, and if you notice
 * something amiss, place a breakpoint at that state value. It's useful for
 * debugging the tests, stopping just before a section that is interesting to
 * step through.
 *
 * You can also place a breakpoint on the cmocka function _fail to stop as soon
 * as an assertion fails.
 */
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

int main(int argc, char **argv) {
    const struct CMUnitTest static_tests[] = {
        cmocka_unit_test(test_static_analysis),
    };

    const struct CMUnitTest functional_tests[] = {
#if defined(IMPLEMENTATION_mtu2)
        cmocka_unit_test(test_init),
        cmocka_unit_test(test_link_ssl_encapsulations),
        cmocka_unit_test(test_link_crypto_encapsulations),
        cmocka_unit_test(test_bufsize_calculations),
        cmocka_unit_test(test_headroom_calculations),
        cmocka_unit_test(test_overhead_calculations),
#endif
    };

    int result = 0, i;

    do_getopt (argc, argv);

    result = cmocka_run_group_tests_name("static_tests", static_tests, NULL, NULL);
    dmsg(D_TEST_INFO, "static tests returned %d", result);
    if (!result) {
        if (sizeof(functional_tests) != 0)
          {
            srand(0);
            result = cmocka_run_group_tests_name("test_typical_inputs", functional_tests, setup_typical, teardown);
            for (i = 0; i < 10000 && result == 0; i++)
              {
                result = cmocka_run_group_tests_name("test_fuzz_inputs", functional_tests, setup_fuzz, teardown);
              }
          }
        else
          return AUTOMAKE_TEST_SKIPPED;
    }

    if (result == 255) /* Cmocka error, failed to test */
      return AUTOMAKE_TEST_HARD_ERROR;

    /* 0 = pass, 1 = fail */
    return !!result;
}
