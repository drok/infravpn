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

#ifndef MTU_H
#define MTU_H

#include "buffer.h"
#include "options.h" /* for OPT_P_PEER_ID */
/*
 * 
 * Packet maninipulation routes such as encrypt, decrypt, compress, decompress
 * are passed a frame buffer that looks like this:
 *
 *    [extra_frame bytes] [mtu bytes] [extra_frame_bytes] [compression overflow bytes]
 *                         ^
 *                   Pointer passed to function points here so that routine
 *                   can make use of extra_frame bytes before pointer
 *                   to prepend headers, etc.
 *
 *    extra_frame bytes is large enough for all encryption related overhead.
 *
 *    mtu bytes will be the MTU size set in the ifconfig statement that configures
 *      the TUN or TAP device such as:
 *
 *      ifconfig $1 10.1.0.2 pointopoint 10.1.0.1 mtu 1450
 *
 *    Compression overflow bytes is the worst-case size expansion that would be
 *    expected if we tried to compress mtu + extra_frame bytes of uncompressible data.
 */

/*
 * Standard ethernet MTU
 */
// #define ETHERNET_MTU       1500

/*
 * It is a fatal error if mtu is less than
 * this value for tun device.
 */
#if !defined(TUN_MTU_MIN)
#define TUN_MTU_MIN        100
#endif

/*
 * Default MTU of network over which tunnel data will pass by TCP/UDP.
 */
#define LINK_MTU_DEFAULT   1500

/* Link MTU to initialize with, pre PMTU discovery.
 */
#define LINK_MTU_STARTUP   250

/*
 * Default MTU of tunnel device.
 */
#if !defined(TUN_MTU_DEFAULT)
#define TUN_MTU_DEFAULT    1500
#endif

/* Initial Receive buffer size. The largest UDP frame is 65535 - IP - UDP
 * Since a server may receive both IPv4 and IPv6, a link receive buffer sized
 * for IPv4 is good for IPv6 also (max datagrams size on IPv6 is smaller than
 * on IPv4)
 * 
 * For practical reasons (traffic over internet is limited to 1500-byte frames),
 * the size of the receive buffers are limited in configure.ac to 1500-ish
 * level by default.
 * 
 * For deployments on gigabit ethernet, where VPN carries data-plane traffic,
 * and performance is desirable, limit can be raised to jumbo-frame (9k-ish)
 * size.
 * 
 * For experimental, the arbitrary limit can be eliminated by undefining
 * LINK_MSS_MAX, which will allow up to 65k datagrams to be received.
 * 
 * In any case, inter-operation between peers with different limits is safe.
 * RFC4821 PMTU discovery will ensure one peer does not send larger UDP frames
 * than the other can receive.
 * 
 * For embedded systems, using smaller buffers will save a lot of RAM,
 * compared to the unconstrained LINK_MSS.
 * In that case, these receive buffers can be safely overridden at build time.
 * If the peer implements the UNRELIABLE_RELIABLE bugfix, or is configured with
 * appropriately small --link-mtu values, these values can be
 * as small as desired, even 200 bytes, which would safely limit the tunnel
 * MTU. In this case, build with -DLINK_MSS=200 (configure with 
 * --enable-link-mss=200)
 * 
 */

#if !defined(LINK_MSS)
#define LINK_RECV_BUFSIZE_STARTUP(f) (IP_MAXPACKET  - \
                                    sizeof(struct openvpn_iphdr) - \
                                    sizeof(struct openvpn_udphdr))
#else
/* Oversize the reduced MSS buffers by one byte to detect truncation of
 * incoming datagrams. 
 */
#define LINK_MSS_GUARD 1
#define LINK_RECV_BUFSIZE_STARTUP(f)  ((LINK_MSS) + LINK_MSS_GUARD)
#endif

/* TUN read buffer will be oversized by 1 byte to detect when a packet larger
 * than the configured MTU arrives (ie, if the MTU is manually changed)
 *
 */
#define TUN_MSDU_GUARD 1

/**  Media Access Control service data unit (MSDU) ie, TUN_MTU
 */
#define TUN_RECV_BUFSIZE_STARTUP (TUN_MTU_DEFAULT + TUN_MSDU_GUARD)

/* Buffer size reserved for PING, OCC (aux)
 * The biggest buffer users are:
 * OCC_REPLY (string)
 * OCC_MTU_LOAD (up to data payload room)
 * 
 * Normally it should be frame_get_data_payload_room (f),
 * but it is allocated by the top multi context, where there a Path MTU does not
 * exist.
 */
#define LINK_AUX_BUFSIZE(f)    LINK_RECV_BUFSIZE_STARTUP(f)

/*
 * MTU Defaults for TAP devices
 */
#define TAP_MTU_EXTRA_DEFAULT  32


#if !defined(FIXME) || !defined(WORKAROUND_UNRELIABLE_RELIABLE)
/*
 * Default MSSFIX value, used for reducing TCP MTU size
 */
#define MSSFIX_DEFAULT     1450

#endif

/**************************************************************************/
/**
 * Packet geometry parameters.
 */

struct frame {
  /* The link struct members are detected after connecting */
  struct {
#if !defined(NDEBUG)
    bool is_init;
#endif

    /* MTU related parameters */
    uint16_t encapsulation;     /* IP + UDP header size, depends on runtime 
                                 * connection proto (ipv4/v6)
                                 */

    uint16_t pmtu;              /**< Maximum packet size to be sent over
                                 *   the external network interface. */

  } link;

  /* The config struct members are set at startup */
  struct {
#if !defined(NDEBUG)
    bool is_init;
#endif

    uint16_t tls_auth_size;     /* Size of AUTH message encapsulation,
                                 * includes opcode, hmac, packet_id, session_id,
                                 * and tls-auth.
                                 * depends on startup --tls-auth configuration
                                 */
    uint16_t headroom;          /* Size needed to wrap link datagrams into
                                 * other protocols. Used to tunnel vpn link
                                 * thorugh a SOCKS5 UDP proxy
                                 */

    /* The crypto struct members are set at startup. In 2.4 they will be set
     * after connecting, and negotiating a cipher.
     */
    struct {
#if !defined(NDEBUG)
      bool is_init;
#endif

      /* Crypto related parameters */
      uint16_t headroom;          /* Size of DATA message encapsulation *header*
                                   * Includes opcode, hmac, and IV, 
                                   * Depends on startup 
                                   * --cipher, --iv
                                   * depends 
                                   */

      uint16_t overhead_sans_pad;
                                  /* Size of DATA message encapsulation, including
                                   * header and block-size related padding.
                                   * Includes opcode, hmac, packetid, IV, but not
                                   * any block-size related padding.
                                   * Depends on startup 
                                   * --cipher, --replay, --iv
                                   */
      uint16_t alignment;         /**< Encryption block size. DATA payload is a
                                   * multiple of this block size.
                                   */
  #if defined(ENABLE_LZO) || defined(ENABLE_FRAGMENT)
      struct {
  #if defined(ENABLE_LZO)
        uint16_t headroom;        /* Headroom within the DATA message needed for
                                   * LZO compression. Typically, this is
                                   * LZO_PREFIX_LEN or 0, depending on startup
                                   * configuration
                                   */
  #endif
  #if defined(ENABLE_FRAGMENT)
        struct {
          uint16_t headroom;      /* size of one fragmentation header. It is
                                   * sizeof(fragment_header_type) or 0, depending
                                   * on startup configuration.
                                   *  fragmentation header.
                                   */
        } fragment;
  #endif
      } lzo;
  #endif
/* Defining the new feature use_peer_id conditional because I want to port the
 * mtu code to earlier versions of the codebase, where peer_id is not
 * implemented.
 */
#if defined (OPT_P_PEER_ID)
      /* While crypto parameters are decided at runtime configuration,
       * other parameters are negotiated at pull time.
       * In later versions (2.4.x?), crypto is also negotiated at pull time,
       * So in that case, merge the pulled_opts and the crypto structs, and
       * initialize them both at pull time.
       */
      struct {
#if !defined(NDEBUG)
        bool is_init;
#endif
        
        bool use_peer_id;

      } pulled_opts;
#endif
    } crypto;
  } config;

};


#if defined(ENABLE_SSL)
#define ACK_SIZE(n) (sizeof (uint8_t) + ((n) ? SID_SIZE : 0) + sizeof (packet_id_type) * (n))
#endif


/* The layers are as follows:
 * Maintainers, please document this as structs { }, and rewrite/remove the
 * scattered buf_prepends
 * 
 * IP               -
 * +-UDP            -
 *   +-DATA         - added by ssl.c: tls_post_encrypt()
 *                  - includes P_OPCODE
 *      +-PAYLOAD   - added by forward.c: encrypt_sign()
 *        +-FRAG    - added by fragment.c: fragment_prepend_flags()
 *                    includes optional startup configuration fragment_header_type.
 *           +-COMP - compression added by lzo.c lzo_compress()
 *                    includes optional startup/build configuration header "LZO_PREFIX"
 *              +-PING      - added by ping.c: check_ping_send_dowork()
 *                            includes 16-byte hardcoded magic string "ping_string"
 *              +-OCC       - added by occ.c: check_send_occ_msg_dowork()
 *                            includes 16-byte hardcoded magic string "occ_magic"
 *                            optional build/startup configuration + runtime conditions
 *                +-OP      - added by occ.c: check_send_occ_msg_dowork()
 *                            includes option strings, exit notification, buffer-size negotiation
 *
 *              +-QUEUE     - added by multi,c: multi_get_queue()
 *                            includes one IP packet with BCAST/MCAST dest.
 *              +-TRAFFIC   - added by forward.c: process_incoming_tun()
 *                            added by crypto.c: openvpn_encrypt()
 *                            optional startup config IV and/or packet_id
 *                            includes one IP packet received from TUN device.
 * 
 *                    
 *   |
 *   +-AUTH                 - added by ssl: write_control_auth()
 *                            includes P_OPCODE, session ID, optional runtime ACKs, 
 *                            optional startup configuration tls-auth HMAC.
 *                            *note* the HMAC covers P_OPCODE and session id, as
 *                            but the fields are reordered in swap_hmac()
 *
 *     +-RELIABLE           - added by reliable_mark_active_outgoing()
 *                            includes packet_id
 *       +-CONTROL          - added by ssl.c: key_state_read_ciphertext()
 *                            SSL data stream
 *       +-HARD_RESET       - scheduled by tls_session_init()
 *                            no data
 *       +-SOFT_RESET       - scheduled by key_state_init()
 *                            no data
 *       +-ACK              - scheduled by tls_process()
 *                            no data
 */

#include "session_id.h"
#include "packet_id.h"

/* 
 * All _ENCAPSULATION macros are with respect to MTU as used in RFCs, ie, IP
 * layer MTU.
 * Eg, LINK_ENCAPSULATION is the number of bytes the OS will add to encapsulate
 * a message written to a DGRAM socket into an IP packet. It includes UDP and IP
 * headers
 */


/* Give no headroom, this will crash something. Fixme. */
#define FIXME_HEADROOM(f) (0)

/* Initialize packetization parameters dependent on runtime configuration.
 */
void
frame_init_config (struct frame *frame,
                   uint16_t tls_auth_size,
                   uint16_t headroom);

/* Initialize packetization parameters dependent on cipher selection.
 */
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
            uint16_t alignment);

/* Initialize packetization parameters dependent on the connected link.
 */
void
frame_init_link (struct frame *frame,
                 int proto);

#if defined (OPT_P_PEER_ID)
/* After the connection's features are negotiated (pull mechanism), the frame
 * parameters change (eg, more headroom for data is needed if switching from a
 * P_DATA_V1 to P_DATA_V2)
 * Update frame parameters at negotiation time.
 */
void
frame_init_pulled_opts (struct frame *frame,
                        bool use_peer_id);
#endif

#if defined(ENABLE_SSL)

uint16_t inline
frame_get_control_payload_room (const struct frame *frame, int num_acks);

uint16_t inline
frame_get_control_headroom (const struct frame *frame, int num_acks);

uint16_t inline
frame_get_probe_encapsulation (const struct frame *frame);

uint16_t inline
frame_get_reliable_encapsulation (const struct frame *frame, int num_acks);

uint16_t inline
frame_get_reliable_headroom (const struct frame *frame, int num_acks);

uint16_t inline
frame_get_control_encapsulation (const struct frame *frame, int num_acks);
#endif

uint16_t inline
frame_get_link_bufsize (const struct frame *frame);

uint16_t inline
frame_get_link_encapsulation (const struct frame *frame);

uint16_t inline
frame_get_link_pmtu (const struct frame *frame);


#if 0
/* The amount of compressed and fragmented data that can be encrypted such that
 * the link PMTU would be filled.
 * 
 */
uint16_t inline
frame_get_data_payload_room (const struct frame *frame);
#endif

/* Headroom needed to packetize ciphertext
 */
uint16_t inline
frame_get_data_ciphertext_headroom (const struct frame *frame);

/* Headroom needed to encrypt the "DATA" layer
 */
uint16_t inline
frame_get_data_headroom (const struct frame *frame);

/* Headroom needed to compress, fragment and encrypt the "COMP" layer
 */
uint16_t inline
frame_get_data_comp_headroom (const struct frame *frame);

#if defined(ENABLE_FRAGMENT)
/* Headroom needed to fragment and encrypt the "FRAG" layer.
 * 
 */
uint16_t inline
frame_get_data_frag_headroom (const struct frame *frame);

/* The amount of compressed data that can be sent for outgoing fragmentation
 */
uint16_t inline
frame_get_data_frag_payload_room (const struct frame *frame);
#endif

uint16_t inline
frame_get_data_overhead (const struct frame *frame, uint16_t datalen);

uint16_t inline
frame_get_data_padding (const struct frame *frame, uint16_t datalen);

uint16_t inline
frame_get_data_padding_max (const struct frame *frame);

uint16_t inline
frame_get_data_comp_encapsulation (const struct frame *frame);

/* The amount of uncompressed data that can be received from TUN, which after
 * compression, fragmenting, and encryption would fill the PMTU exactly.
 * 
 * If the host were to send datagrams with PMTUDISC_DO flag set, those larger
 * than this would be rejected with PTB (Packet Too Big) ICMPs.
 * 
 * Without the PMTUDISC_DO flag, datagrams larger than this should be fragmented
 * by the host OS before writing to the TUN device. Otherwise, internet routers
 * en-route to the destination will fragment the encrypted datagram.
 * 
 * In client mode (ie, a single connection using the TUN), the TUN MTU can be
 * set to this value.
 */

uint16_t inline
frame_get_data_comp_payload_room (const struct frame *frame);

/* Calculate the amount of overhead needed to compress, fragment and encrypt
 * a TUN packet of a given length.
 * 
 */
uint16_t inline
frame_get_data_comp_overhead (const struct frame *frame, uint16_t datalen);

/* Calculate the minimum amount of overhead needed to compress, fragment and
 * encrypt a TUN packet of optimal length.
 * 
 * This is helpful to calculate the maximum possible TUN MTU given a LINK MTU,
 * as it returns the minimum amount of overhead by assuming a packet size that
 * requires the minimum amount of encryption padding for the configured cipher
 */
/*
uint16_t inline
frame_get_data_comp_min_overhead (const struct frame *frame);
*/
uint16_t inline
frame_get_buf_size (const struct frame *frame);
    
#define ENCRYPTION_BUFSIZE(f,plaintext_size) \
            plaintext_size + \
            frame_get_data_overhead(f, plaintext_size)

#define DECRYPTION_BUFSIZE(f,ciphertext_size) \
            ciphertext_size - \
            frame_get_data_headroom(f)

#define LZO_COMPRESSION_BUFSIZE(f,input_size) \
            input_size + \
            LZO_PREFIX_LEN + \
            LZO_EXTRA_BUFFER (input_size) + \
            frame_get_data_overhead(f, input_size + LZO_PREFIX_LEN + LZO_EXTRA_BUFFER (input_size))


#define LZO_DECOMPRESSION_BUFSIZE(f,input_size) \
            input_size - \
            LZO_PREFIX_LEN - \
            LZO_SHRINK_BUFFER (input_size) - \
            frame_get_data_headroom(f)


/*
 * Function prototypes.
 */

void frame_print (const struct frame *frame,
		  int level,
		  const char *prefix);

void frame_set_mtu (struct frame *frame, uint16_t mtu);

/*
 * allocate a buffer for socket or tun layer
 */
void alloc_buf_sock_tun (struct buffer *buf,
			 const struct frame *frame,
			 const bool tuntap_buffer);

/*
 * EXTENDED_SOCKET_ERROR_CAPABILITY functions -- print extra error info
 * on socket errors, such as PMTU size.  As of 2003.05.11, only works
 * on Linux 2.4+.
 */

#if EXTENDED_SOCKET_ERROR_CAPABILITY

void set_sock_extended_error_passing (int sd);
const char *format_extended_socket_error (int fd, int *mtu, struct gc_arena *gc);

#endif

#endif
