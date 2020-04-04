/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "common.h"
#include "buffer.h"
#include "error.h"
#include "integer.h"
#include "mtu.h"
#include "socket.h"
#include "options.h" /* For OPT_P_PEER_ID */
#include "ssl.h" /* for P_OPCODE_*_LEN */

#include "memdbg.h"

#if defined (OPT_P_PEER_ID)
#define RELIABLE_HEADROOM(f,numacks) ( \
                (f)->config.headroom + \
                P_OPCODE_CONTROL_LEN + \
                SID_SIZE + \
                ACK_SIZE(numacks))
#else
#define RELIABLE_HEADROOM(f,numacks) ( \
                (f)->config.headroom + \
                P_OPCODE_LEN + \
                SID_SIZE + \
                ACK_SIZE(numacks))
#endif

#define RELIABLE_ENCAPSULATION(f,numacks) \
                ((f)->link.encapsulation + \
                RELIABLE_HEADROOM(f,numacks) \
                )

#define CONTROL_HEADROOM(f,numacks) \
                ((f)->config.tls_auth_size + \
                sizeof (packet_id_type) + \
                RELIABLE_HEADROOM(f,numacks))

#define CONTROL_ENCAPSULATION(f,numacks) \
                ((f)->config.tls_auth_size + \
                sizeof (packet_id_type) + \
                RELIABLE_ENCAPSULATION(f, numacks))

/* a PROBE is CONTROL with 0 acks */
#define PROBE_ENCAPSULATION(f)  CONTROL_ENCAPSULATION(f,0)

/*
 * #define DATA_HEADROOM(f) ( \
                (f)->config.headroom + \
                ((f)->config.crypto.headroom))
*/
#if defined(ENABLE_SSL)
#if defined (OPT_P_PEER_ID)
#define DATA_ENCAPSULATION(f) \
                ((f)->link.encapsulation + \
                (f)->config.headroom + \
                ((f)->config.crypto.pulled_opts.use_peer_id ? P_OPCODE_DATA_V2_LEN :  P_OPCODE_DATA_V1_LEN) + \
                (f)->config.crypto.overhead_sans_pad)
#else
#define DATA_ENCAPSULATION(f) \
                ((f)->link.encapsulation + \
                (f)->config.headroom + \
                P_OPCODE_LEN + \
                (f)->config.crypto.overhead_sans_pad)
#endif
#else
#define DATA_ENCAPSULATION(f) \
                ((f)->link.encapsulation + \
                (f)->config.headroom + \
                (f)->config.crypto.overhead_sans_pad)
#endif

/* allocate a buffer for socket or tun layer */
void
alloc_buf_sock_tun (struct buffer *buf,
		    const struct frame *frame,
		    const bool tuntap_buffer)
{
  /* allocate buffer for overlapped I/O */
  *buf = alloc_buf (ENCRYPTION_BUFSIZE(frame, LINK_RECV_BUFSIZE_STARTUP(frame)));
  bool success = buf_init (buf, frame_get_data_headroom (frame));
  ASSERT (success && "Link socket transmit buffer initialized successfully");
  /* FIXME: I'm pretty sure this is not correct.
   * What is this buffer used for? Sending? Receiving? Link or TUN?
   * Assuming this is a link receive buffer.
   * But what is the meaning of setting the len, and checking if it's safe to add
   * 0 bytes??
   */
  buf->len = tuntap_buffer ? TUN_RECV_BUFSIZE_STARTUP : LINK_RECV_BUFSIZE_STARTUP(frame);
  ASSERT (buf_safe (buf, 0));
}

/*
 * Set the tun MTU dynamically.
 */
void
frame_set_mtu (struct frame *frame, uint16_t mtu)
{
  ASSERT (IS_INITIALIZED(&frame->link));

  frame->link.pmtu = mtu;
}

void
frame_init_config (struct frame *frame,
                 uint16_t tls_auth_size,
                 uint16_t headroom)
{
  ASSERT (!IS_INITIALIZED(&frame->config) && "Frame config is only initialized once");

#if !defined(NDEBUG)
  frame->config.is_init = true;
#endif

  frame->config.tls_auth_size = tls_auth_size;
  frame->config.headroom = headroom;

  frame_print (frame, D_MTU_INFO, "Frame Init Config:");
}

void
frame_init_crypto (struct frame *frame,
#if defined(ENABLE_LZO)
            uint16_t lzo_headroom,
#endif
#if defined(ENABLE_FRAGMENT)
            uint16_t fragment_headroom,
#endif
            uint16_t headroom,
            uint16_t overhead,
            uint16_t alignment)
{

  ASSERT (!IS_INITIALIZED(&frame->config.crypto) && "Frame crypto is only initialized once");

#if !defined(NDEBUG)
  frame->config.crypto.is_init = true;
#endif

  frame->config.crypto.headroom          = headroom;
  frame->config.crypto.overhead_sans_pad = overhead;
  frame->config.crypto.alignment         = alignment;

#if defined(ENABLE_LZO)
  frame->config.crypto.lzo.headroom      = lzo_headroom;
#endif
#if defined(ENABLE_FRAGMENT)
  frame->config.crypto.lzo.fragment.headroom
                                         = fragment_headroom;
#endif

  frame->config.crypto.pulled_opts.use_peer_id = false; /* Default setting */

  frame_print (frame, D_MTU_INFO, "Frame Init Crypto:");
}

#if defined (OPT_P_PEER_ID)
void
frame_init_pulled_opts (struct frame *frame,
                        bool use_peer_id)
{
  ASSERT (!IS_INITIALIZED(&frame->config.crypto.pulled_opts) &&
          "Frame pulled_opts is only initialized once");

#if !defined(NDEBUG)
  frame->config.crypto.pulled_opts.is_init = true;
#endif

  frame->config.crypto.pulled_opts.use_peer_id = use_peer_id;
}
#endif

void
frame_init_link (struct frame *frame,
                 int proto)
{
  ASSERT (!IS_INITIALIZED(&frame->link) && "Frame Link is only initialized once");

#if !defined(NDEBUG)
  frame->link.is_init = true;
#endif

  frame->link.pmtu = LINK_MTU_STARTUP;
  frame->link.encapsulation = datagram_overhead(proto);

  frame_print (frame, D_MTU_INFO, "Frame Init Link:");
}

#if 0
/* 
 */
uint16_t inline
frame_get_data_payload_room (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->link));

  return frame->link.pmtu - frame->link.encapsulation -
          frame_get_data_overhead(frame, 0);
}
#endif

/* Headroom needed to packetize ciphertext
 */
uint16_t inline
frame_get_data_ciphertext_headroom (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->config.crypto.pulled_opts));

  uint16_t headroom = 0;
#if defined (ENABLE_SSL)
#if defined (OPT_P_PEER_ID)
  headroom += frame->config.crypto.pulled_opts.use_peer_id ? P_OPCODE_DATA_V2_LEN : P_OPCODE_DATA_V1_LEN;
#else
  headroom += P_OPCODE_LEN;
#endif
#endif
  return headroom;
}

uint16_t inline
frame_get_data_headroom (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->config));
  ASSERT (IS_INITIALIZED(&frame->config.crypto));
  ASSERT (IS_INITIALIZED(&frame->config.crypto.pulled_opts));

  uint16_t headroom = frame->config.headroom +
                    frame->config.crypto.headroom;

  headroom += frame_get_data_ciphertext_headroom (frame);

  return headroom;
}

uint16_t inline
frame_get_data_comp_headroom (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->config));
  ASSERT (IS_INITIALIZED(&frame->config.crypto));
  ASSERT (IS_INITIALIZED(&frame->config.crypto.pulled_opts));

  uint16_t headroom = frame_get_data_headroom(frame);

#if defined(ENABLE_LZO)
  headroom += frame->config.crypto.lzo.headroom;
#endif
#if defined(ENABLE_FRAGMENT)
  headroom += frame->config.crypto.lzo.fragment.headroom;
#endif

  return headroom;
}

#if defined(ENABLE_FRAGMENT)
uint16_t inline
frame_get_data_frag_headroom (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->config));
  ASSERT (IS_INITIALIZED(&frame->config.crypto));

  uint16_t headroom = frame_get_data_headroom(frame);

  headroom += frame->config.crypto.lzo.fragment.headroom;

  return headroom;
}

uint16_t inline
frame_get_data_frag_payload_room (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->link));
  ASSERT (IS_INITIALIZED(&frame->config.crypto));

  uint16_t room = frame->link.pmtu - DATA_ENCAPSULATION(frame);
  /* Trim the room to alignment boundary, and deduct the minimum necessary
   * padding (1 byte)
   */
  if (frame->config.crypto.alignment)
    room -= (room % frame->config.crypto.alignment + 1);
  
  room -= frame->config.crypto.lzo.fragment.headroom;
  
  return room;
}

#endif

uint16_t inline
frame_get_data_comp_overhead (const struct frame *frame, uint16_t datalen)
{
  ASSERT (IS_INITIALIZED(&frame->config.crypto));

  uint16_t fragmented = 
#if defined(ENABLE_LZO)
            frame->config.crypto.lzo.headroom +
#endif
#if defined(ENABLE_FRAGMENT)
            frame->config.crypto.lzo.fragment.headroom +
#endif
            datalen;

    return 
#if defined(ENABLE_LZO)
            frame->config.crypto.lzo.headroom +
#endif
#if defined(ENABLE_FRAGMENT)
            frame->config.crypto.lzo.fragment.headroom +
#endif
            frame_get_data_overhead (frame, fragmented);
}

/*
uint16_t inline
frame_get_data_comp_min_overhead (const struct frame *frame, uint16_t datalen)
{
  return frame_get_data_comp_overhead(frame,
                   frame->crypto.alignment ? frame->crypto.alignment - 1 : 0);
}
*/
uint16_t inline
frame_get_data_comp_encapsulation (const struct frame *frame)
{
  return frame_get_link_encapsulation(frame) +
         frame_get_data_comp_headroom(frame);
}

uint16_t inline
frame_get_data_comp_payload_room (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->link));
  ASSERT (IS_INITIALIZED(&frame->config.crypto));

  uint16_t room = frame->link.pmtu - DATA_ENCAPSULATION(frame);
  /* Trim the room to alignment boundary, and deduct the minimum necessary
   * padding (1 byte)
   */
  if (frame->config.crypto.alignment)
    room -= (room % frame->config.crypto.alignment + 1);
  
#if defined(ENABLE_LZO)
    room -= frame->config.crypto.lzo.headroom;
#endif
#if defined(ENABLE_FRAGMENT)
    room -= frame->config.crypto.lzo.fragment.headroom;
#endif
  
  return room;
}

uint16_t inline
frame_get_data_overhead (const struct frame *frame, uint16_t datalen)
{
  ASSERT (IS_INITIALIZED(&frame->config));
  ASSERT (IS_INITIALIZED(&frame->config.crypto));

  return    frame_get_data_headroom(frame) +
            frame->config.crypto.overhead_sans_pad - frame->config.crypto.headroom +
            frame_get_data_padding (frame, datalen /* data + packet_id */);
}

uint16_t inline
frame_get_data_padding (const struct frame *frame, uint16_t datalen)
{
  ASSERT (IS_INITIALIZED(&frame->config.crypto));

  uint16_t replay = frame->config.crypto.overhead_sans_pad - frame->config.crypto.headroom;
  uint16_t padding_len_pkcs7 = frame->config.crypto.alignment ? frame->config.crypto.alignment - 
          ((datalen+replay) % frame->config.crypto.alignment) : 0;
  return padding_len_pkcs7;
}

uint16_t inline
frame_get_data_padding_max (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->config.crypto));
  return frame->config.crypto.alignment;
}

uint16_t inline
frame_get_link_encapsulation (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->link));

  return frame->link.encapsulation;
}

uint16_t inline
frame_get_link_pmtu (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->link));

  return frame->link.pmtu;
}

#if defined(ENABLE_SSL)
uint16_t inline
frame_get_reliable_encapsulation (const struct frame *frame, int num_acks)
{
  ASSERT (IS_INITIALIZED(&frame->link));

  return RELIABLE_ENCAPSULATION(frame,num_acks);
}

uint16_t inline
frame_get_reliable_headroom (const struct frame *frame, int num_acks)
{
  ASSERT (IS_INITIALIZED(&frame->config));

  return RELIABLE_HEADROOM(frame,num_acks);
}

uint16_t inline
frame_get_control_encapsulation (const struct frame *frame, int num_acks)
{
  ASSERT (IS_INITIALIZED(&frame->config));
  ASSERT (IS_INITIALIZED(&frame->link));

  return CONTROL_ENCAPSULATION(frame,num_acks);
}

uint16_t inline
frame_get_control_headroom (const struct frame *frame, int num_acks)
{
  ASSERT (IS_INITIALIZED(&frame->config));

  return CONTROL_HEADROOM(frame,num_acks);
}

uint16_t inline
frame_get_probe_encapsulation (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->config));
  ASSERT (IS_INITIALIZED(&frame->link));

  return CONTROL_ENCAPSULATION(frame,0);
}

/* Amount of DATA carried in a Control message with num_acks ACKs that will fit
 * in the PMTU.
 * 
 * This is socket bufsize minus opcode, SID, ACKs, packet_ID and TLS-AUTH
 */
uint16_t inline
frame_get_control_payload_room (const struct frame *frame, int num_acks)
{
  ASSERT (IS_INITIALIZED(&frame->config));
  ASSERT (IS_INITIALIZED(&frame->link));
  
  return frame->link.pmtu -
          CONTROL_ENCAPSULATION(frame, num_acks);
}
#endif

/* Buffer size needed to send() to the socket descriptor, and fill the
 * PMTU exactly?
 */
uint16_t inline
frame_get_link_bufsize (const struct frame *frame)
{
  ASSERT (IS_INITIALIZED(&frame->config));
  ASSERT (IS_INITIALIZED(&frame->link));
  
  return frame->link.pmtu - frame->link.encapsulation;
}

void
frame_print (const struct frame *frame,
	     int level,
	     const char *prefix)
{
  struct gc_arena gc = gc_new ();
  struct buffer out;
  if (check_debug_level(D_MTU_INFO))
    {
      out = alloc_buf_gc (256, &gc);
      if (prefix)
        buf_printf (&out, "%s ", prefix);

      buf_printf (&out, "[");
#if !defined(NDEBUG)
      if (frame->config.is_init)
#endif
        {
          buf_printf (&out, " TLS-AUTH:%d", frame->config.tls_auth_size);  /* auth size */
          buf_printf (&out, " LHR:%d", frame->config.headroom);  /* socks5 H/R */
        }
#if !defined(NDEBUG)
      if (frame->link.is_init)
#endif
        {
          buf_printf (&out, " PMTU:%d", frame->link.pmtu);   /* path mtu */
          buf_printf (&out, " P:%d", frame->link.encapsulation);/* proto overhead */
        }
#if !defined(NDEBUG)
      if (frame->config.crypto.is_init)
#endif
        {
          buf_printf (&out, " CHR:%d",  frame->config.crypto.headroom);   /* data overhead */
          buf_printf (&out, " COH:%d",  frame->config.crypto.overhead_sans_pad); /* data overhead */
          buf_printf (&out, " CA:%d", frame->config.crypto.alignment); /* data alignment */
      
#if defined(ENABLE_LZO)
          buf_printf (&out, " C:%d", frame->config.crypto.lzo.headroom);
#endif
#if defined(ENABLE_FRAGMENT)
          buf_printf (&out, " F:%d", frame->config.crypto.lzo.fragment.headroom);
#endif
#if defined (OPT_P_PEER_ID)
          buf_printf (&out, " PI:%d", frame->config.crypto.pulled_opts.use_peer_id);
#endif
        }
      buf_printf (&out, " ]");

      msg (level, "%s", out.data);
      gc_free (&gc);
    }
}

#if EXTENDED_SOCKET_ERROR_CAPABILITY

struct probehdr
{
  uint32_t ttl;
  struct timeval tv;
};

const char *
format_extended_socket_error (int fd, int *mtu, struct gc_arena *gc)
{
  int res;
  struct probehdr rcvbuf;
  struct iovec iov;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct sock_extended_err *e;
  struct sockaddr_in addr;
  struct buffer out = alloc_buf_gc (256, gc);
  char *cbuf = (char *) gc_malloc (256, false, gc);

  *mtu = 0;

  while (true)
    {
      memset (&rcvbuf, -1, sizeof (rcvbuf));
      iov.iov_base = &rcvbuf;
      iov.iov_len = sizeof (rcvbuf);
      msg.msg_name = (uint8_t *) &addr;
      msg.msg_namelen = sizeof (addr);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_flags = 0;
      msg.msg_control = cbuf;
      msg.msg_controllen = 256; /* size of cbuf */

      res = recvmsg (fd, &msg, MSG_ERRQUEUE);
      if (res < 0)
	goto exit;

      e = NULL;

      for (cmsg = CMSG_FIRSTHDR (&msg); cmsg; cmsg = CMSG_NXTHDR (&msg, cmsg))
	{
	  if (cmsg->cmsg_level == SOL_IP)
	    {
	      if (cmsg->cmsg_type == IP_RECVERR)
		{
		  e = (struct sock_extended_err *) CMSG_DATA (cmsg);
		}
	      else
		{
		  buf_printf (&out ,"CMSG=%d|", cmsg->cmsg_type);
		}
	    }
	}
      if (e == NULL)
	{
	  buf_printf (&out, "NO-INFO|");
	  goto exit;
	}

      switch (e->ee_errno)
	{
	case ETIMEDOUT:
	  buf_printf (&out, "ETIMEDOUT|");
	  break;
	case EMSGSIZE:
	  buf_printf (&out, "EMSGSIZE Path-MTU=%d|", e->ee_info);
	  *mtu = e->ee_info;
	  break;
	case ECONNREFUSED:
	  buf_printf (&out, "ECONNREFUSED|");
	  break;
	case EPROTO:
	  buf_printf (&out, "EPROTO|");
	  break;
	case EHOSTUNREACH:
	  buf_printf (&out, "EHOSTUNREACH|");
	  break;
	case ENETUNREACH:
	  buf_printf (&out, "ENETUNREACH|");
	  break;
	case EACCES:
	  buf_printf (&out, "EACCES|");
	  break;
	default:
	  buf_printf (&out, "UNKNOWN|");
	  break;
	}
    }

 exit:
  buf_rmtail (&out, '|');
  return BSTR (&out);
}

void
set_sock_extended_error_passing (int sd)
{
  int on = 1;
  if (setsockopt (sd, SOL_IP, IP_RECVERR, &on, sizeof (on)))
    msg (M_WARN | M_ERRNO,
	 "Note: enable extended error passing on TCP/UDP socket failed (IP_RECVERR)");
}

#endif
