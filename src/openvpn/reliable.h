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


/**
 * @file
 * Reliability Layer module header file.
 */


#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)

#ifndef RELIABLE_H
#define RELIABLE_H

#include "basic.h"
#include "buffer.h"
#include "packet_id.h"
#include "session_id.h"
#include "mtu.h"
#include "rfc4821.h"

/** @addtogroup reliable
 *  @{ */


#define EXPONENTIAL_BACKOFF

#define RELIABLE_ACK_SIZE 8     /**< The maximum number of packet IDs
                                 *   waiting to be acknowledged which can
                                 *   be stored in one \c reliable_ack
                                 *   structure. */

/*
 * Define number of buffers for send and receive in the reliability layer.
 */
#define RELIABLE_N_SEND_BUFFERS  4
#define RELIABLE_N_REC_BUFFERS   8

/**
 * The acknowledgment structure in which packet IDs are stored for later
 * acknowledgment.
 */
struct reliable_ack
{
  int len;
  packet_id_type packet_id[RELIABLE_ACK_SIZE];
};

/**
 * The structure in which the reliability layer stores a single incoming
 * or outgoing packet.
 */
struct rec_reliable_entry
{
  bool active;
  packet_id_type packet_id;
  struct buffer buf;
};

struct send_reliable_entry
{
  enum {
    REL_INACTIVE = 0,      /* never been sent */
    REL_ACKED,             /* previously sent and acked */
    REL_ACTIVE,            /* real packet in flight */
    REL_PMTUD_PROBE,       /* probe packet in flight */
  } active;
  interval_t timeout;
  time_t next_try;
  struct timeval sent_time;
  packet_id_type packet_id;
  int opcode;
  struct buffer buf;
};

/**
 * The reliability layer storage structure for one VPN tunnel's control
 * channel in one direction.
 */

struct send_reliable
{
  interval_t initial_timeout;
  packet_id_type packet_id;
  int offset;
  interval_t rtt;
  struct send_reliable_entry array[RELIABLE_N_SEND_BUFFERS];

  /* Packetization Layer Path MTU discovery state */
  /* FIXME: This does not belong here, but in the client's c2 context
   * maybe inside c2.frame, but there are 2 sets of reliable buffers, one for
   * each keystate[0,1]
   * That also seems wrong, as there should be one packet_id sequence, regardless
   * which keystate is active, thus one set of reliable buffers.
   * Maybe the reliable structure should also live in c2.
   * When the PMTU is updated, the buffers in the send_reliable need to be
   * reallocated. Not just the active send_reliable set, but both sets??
   * What happens the active keyset changes, and say, packets arrived in the order
   * 
   * pid=10[key1], pid=12[key2], pid=11[key1] ... are they handled in the correct order?
   * ie, pids 10, 11, 12 with keys 1, 1, 2 respectively? If yes, and they should,
   * then there should be one reliable struct under the context, not under the
   * keyset.
   * 
   * Path MTU discovery should not need to be redone when keys get renegotiated.
   */
  struct plpmtud pmtud_state;
};

struct rec_reliable
{
  packet_id_type packet_id;
  struct rec_reliable_entry array[RELIABLE_N_REC_BUFFERS];
};

/**************************************************************************/
/** @name Functions for processing incoming acknowledgments
 *  @{ */

/**
 * Read an acknowledgment record from a received packet.
 *
 * This function reads the packet ID acknowledgment record from the packet
 * contained in \a buf.  If the record contains acknowledgments, these are
 * stored in \a ack.  This function also compares the packet's session ID
 * with the expected session ID \a sid, which should be equal.
 *
 * @param ack The acknowledgment structure in which received
 *     acknowledgments are to be stored.
 * @param buf The buffer containing the packet.
 * @param sid The expected session ID to compare to the session ID in
 *     the packet.
 *
 * @return
 * @li True, if processing was successful.
 * @li False, if an error occurs during processing.
 */
bool reliable_ack_read (struct reliable_ack *ack,
			struct buffer *buf, const struct session_id *sid);

/**
 * Remove acknowledged packets from a reliable structure.
 *
 * @param rel The reliable structure storing sent packets.
 * @param ack The acknowledgment structure containing received
 *     acknowledgments.
 */
void reliable_send_purge (struct send_reliable *rel, struct reliable_ack *ack,
                         struct frame *frame);

/**
 * Remove lost packets from a reliable structure. Used for PMTU discovery.
 * Assumes that only PMTU probes will be lost.
 *
 * @param rel The reliable structure storing sent packets.
 * @param buf The buffer that was lost
 * @param frame The MTU frame parameters associated with this reliable struct
 *
 * @return true if discovery is finished.
 */
bool
reliable_send_lost (struct send_reliable *rel,
                    struct buffer *buf,
                    struct frame *frame);

/** @} name Functions for processing incoming acknowledgments */


/**************************************************************************/
/** @name Functions for processing outgoing acknowledgments
 *  @{ */

/**
 * Check whether an acknowledgment structure contains any
 *     packet IDs to be acknowledged.
 *
 * @param ack The acknowledgment structure to check.
 *
 * @return
 * @li True, if the acknowledgment structure is empty.
 * @li False, if there are packet IDs to be acknowledged.
 */
static inline bool
reliable_ack_empty (struct reliable_ack *ack)
{
  return !ack->len;
}

/**
 * Write a packet ID acknowledgment record to a buffer.
 *
 * @param ack The acknowledgment structure containing packet IDs to be
 *     acknowledged.
 * @param buf The buffer into which the acknowledgment record will be
 *     written.
 * @param sid The session ID of the VPN tunnel associated with the
 *     packet IDs to be acknowledged.
 * @param max The maximum number of acknowledgments to be written in
 *     the record.
 * @param prepend If true, prepend the acknowledgment record in the
 *     buffer; if false, write into the buffer's current position.
 *
 * @return
 * @li True, if processing was successful.
 * @li False, if an error occurs during processing.
 */
bool reliable_ack_write (struct reliable_ack *ack,
			 struct buffer *buf,
			 const struct session_id *sid, int max, bool prepend);

/** @} name Functions for processing outgoing acknowledgments */


/**************************************************************************/
/** @name Functions for initialization and cleanup
 *  @{ */

/**
 * Initialize a send_reliable structure.
 *
 * @param rel The send_reliable structure to initialize.
 * @param buf_size The size of the buffers in which packets will be
 *     stored.
 * @param offset The size of reserved space at the beginning of the
 *     buffers to allow efficient header prepending.
 */
void reliable_send_init (struct send_reliable *rel, int buf_size, int offset);

/**
 * Initialize a rec_reliable structure.
 *
 * @param rel The rec_reliable structure to initialize.
 * @param buf_size The size of the buffers in which packets will be
 *     stored.
 */
void reliable_rec_init (struct rec_reliable *rel, int buf_size);

/**
 * Free allocated memory associated with a send_reliable structure.
 *
 * @param rel The send_reliable structure to clean up.
 */
void reliable_send_free (struct send_reliable *rel);

/**
 * Free allocated memory associated with a rec_reliable structure.
 *
 * @param rel The rec_reliable structure to clean up.
 */
void reliable_rec_free (struct rec_reliable *rel);

/* How many bytes will it take to transmit n acks in one frame? */
int reliable_ack_get_frame_extra (int n_acks);

/* Change the buffer size */
void reliable_realloc (struct send_reliable *rel, int buf_size);

/** @} name Functions for initialization and cleanup */


/**************************************************************************/
/** @name Functions for inserting incoming packets
 *  @{ */

/**
 * Check whether a reliable structure has any free buffers
 *     available for use.
 *
 * @param rel The reliable structure to check.
 *
 * @return
 * @li True, if at least one buffer is available for use.
 * @li False, if all the buffers are active.
 */
bool reliable_can_get (const struct rec_reliable *rel);

/**
 * Check that a received packet's ID is not a replay.
 *
 * @param rel The reliable structure for handling this VPN tunnel's
 *     received packets.
 * @param id The packet ID of the received packet.
 *
 * @return
 * @li True, if the packet ID is not a replay.
 * @li False, if the packet ID is a replay.
 */
bool reliable_not_replay (const struct rec_reliable *rel, packet_id_type id);

/**
 * Check that a received packet's ID can safely be stored in
 *     the reliable structure's processing window.
 *
 * This function checks the difference between the received packet's ID
 * and the lowest non-acknowledged packet ID in the given reliable
 * structure.  If that difference is larger than the total number of
 * packets which can be stored, then this packet cannot be stored safely,
 * because the reliable structure could possibly fill up without leaving
 * room for all intervening packets.  In that case, this received packet
 * could break the reliable structure's sequentiality, and must therefore
 * be discarded.
 *
 * @param rel The reliable structure for handling this VPN tunnel's
 *     received packets.
 * @param id The packet ID of the received packet.
 *
 * @return
 * @li True, if the packet can safely be stored.
 * @li False, if the packet does not fit safely in the reliable
 *     structure's processing window.
 */
bool reliable_wont_break_sequentiality (const struct rec_reliable *rel, packet_id_type id);

/**
 * Read the packet ID of a received packet.
 *
 * @param buf The buffer containing the received packet.
 * @param pid A pointer where the packet's packet ID will be written.
 *
 * @return
 * @li True, if processing was successful.
 * @li False, if an error occurs during processing.
 */
bool reliable_ack_read_packet_id (struct buffer *buf, packet_id_type *pid);

/**
 * Get the buffer of a free %reliable entry in which to store a
 *     incoming packet.
 *
 * @param rel The reliable structure in which to search for a free
 *     entry.
 *
 * @return A pointer to a buffer of a free entry in the \a rel
 *     reliable structure.  If there are no free entries available, this
 *     function returns NULL.
 */
struct buffer *reliable_get_rec_buf (struct rec_reliable *rel);

/**
 * Mark the %reliable entry associated with the given buffer as active
 * incoming.
 *
 * @param rel The reliable structure associated with this packet.
 * @param buf The buffer into which the packet has been copied.
 * @param pid The packet's packet ID.
 * @param opcode The packet's opcode.
 */
void reliable_mark_active_incoming (struct rec_reliable *rel, struct buffer *buf,
				    packet_id_type pid);

/**
 * Record a packet ID for later acknowledgment.
 *
 * @param ack The acknowledgment structure which stores this VPN
 *     tunnel's packet IDs for later acknowledgment.
 * @param pid The packet ID of the received packet which should be
 *     acknowledged.
 *
 * @return
 * @li True, if the packet ID was added to \a ack.
 * @li False, if the packet ID was already present in \a ack or \a ack
 *     has no free space to store any more packet IDs.
 */
bool reliable_ack_acknowledge_packet_id (struct reliable_ack *ack, packet_id_type pid);

/** @} name Functions for inserting incoming packets */


/**************************************************************************/
/** @name Functions for extracting incoming packets
 *  @{ */

/**
 * Get the buffer of the next sequential and active entry.
 *
 * @param rel The reliable structure from which to retrieve the
 *     buffer.
 *
 * @return A pointer to the buffer of the entry with the next
 *     sequential key ID.  If no such entry is present, this function
 *     returns NULL.
 */
struct buffer *reliable_get_buf_sequenced (struct rec_reliable *rel);

/**
 * Remove an entry from a reliable structure.
 *
 * @param rel The reliable structure associated with the given buffer.
 * @param buf The buffer of the reliable entry which is to be removed.
 * @param inc_pid If true, the reliable structure's packet ID counter
 *     will be incremented.
 */
void reliable_mark_deleted (struct rec_reliable *rel, struct buffer *buf, bool inc_pid);

/** @} name Functions for extracting incoming packets */


/**************************************************************************/
/** @name Functions for inserting outgoing packets
 *  @{ */

/**
 * Get the buffer of free reliable entry and check whether the
 *     outgoing acknowledgment sequence is still okay.
 *
 * @param rel The reliable structure in which to search for a free
 *     entry.
 *
 * @return A pointer to a buffer of a free entry in the \a rel
 *     reliable structure.  If there are no free entries available, this
 *     function returns NULL.  If the outgoing acknowledgment sequence is
 *     broken, this function also returns NULL.
 */
struct buffer *reliable_get_buf_output_sequenced (struct send_reliable *rel);

/**
 * Mark the reliable entry associated with the given buffer as
 *     active outgoing.
 *
 * @param rel The reliable structure for handling this VPN tunnel's
 *     outgoing packets.
 * @param buf The buffer previously returned by \c
 *     reliable_get_buf_output_sequenced() into which the packet has been
 *     copied.
 * @param opcode The packet's opcode.
 * @param activation Whether this packet will be a regular control packet
 *              (REL_ACTIVE) or an MTU probe packet (REL_PMTUD_PROBE)
 * @param overhead The amount of packetization overhead bytes: TUN_LINK_DELTA(frame)
 * @return true if the packet was successfully marked, false if not marked.
 */
bool reliable_mark_active_outgoing (struct send_reliable *rel,
                                    struct buffer *buf,
                                    int opcode,
                                    int activation,
                                    int overhead);

/** @} name Functions for inserting outgoing packets */






/**************************************************************************/
/** @name Functions for extracting outgoing packets
 *  @{ */

/**
 * Check whether a reliable structure has any active entries
 *     ready to be (re)sent.
 * Also handles expired PMTU probes.
 *
 * @param rel The reliable structure to check.
 * @param frame MTU parameters associated with this link.
 *
 * @return
 * @li True, if there are active entries ready to be (re)sent
 *     president.
 * @li False, if there are no active entries, or the active entries
 *     are not yet ready for resending.
 */
bool reliable_can_send (struct send_reliable *rel, struct frame *frame);

/**
 * Get the next packet to send to the remote peer.
 *
 * This function looks for the active entry ready for (re)sending with the
 * lowest packet ID, and returns the buffer associated with it.  This
 * function also resets the timeout after which that entry will become
 * ready for resending again.
 *
 * @param rel The reliable structure to check.
 * @param opcode A pointer to an integer in which this function will
 *     store the opcode of the next packet to be sent.
 * @param pmtud Path MTU discovery state
 *
 * @return A pointer to the buffer of the next entry to be sent, or
 *     NULL if there are no entries ready for (re)sending present in the
 *     reliable structure.  If a valid pointer is returned, then \a opcode
 *     will point to the opcode of that packet.
 */
struct buffer *reliable_send (struct send_reliable *rel, int *opcode);


/**
 * Resequence packets that have already be sent, and re-queue them to be resent
 * 
 * This is needed to support the link params negotiation in the initial
 * HARD_RESET, where the pid field (and start of sequence), is used to pass
 * an arbitrary parameter ("my receive buffer size"). Old servers do not accept
 * a HARD_RESET with a pid other than 0 so they don't ACK the reset with link
 * parameters. They respond with their own HARD_RESET pid=0, so a new client
 * must play along and revert to expected behaviour (HARD_RESET pid=0)
 * 
 * In reality, only one packet is in the reliable structure at the point this
 * function is called: the initial HARD_RESET with non-zero pid.
 * 
 * @param rel       The reliable structure to resequence
 * @param offset    The offset to be added to each packet
 */
void reliable_renumber (struct send_reliable *rel, int offset);

/** @} name Functions for extracting outgoing packets */

/**************************************************************************/
/** @name Miscellaneous functions
 *  @{ */

/**
 * Check whether a reliable structure is empty.
 *
 * @param rel The reliable structure to check.
 *
 * @return
 * @li True, if there are no active entries in the given reliable
 *     structure.
 * @li False, if there is at least one active entry present.
 */
bool reliable_empty (const struct send_reliable *rel);

/**
 * Determined how many seconds until the earliest resend should
 *     be attempted.
 *
 * @param rel The reliable structured to check.
 *
 * @return The interval in seconds until the earliest resend attempt
 *     of the outgoing packets stored in the \a rel reliable structure. If
 *     the next time for attempting resending of one or more packets has
 *     already passed, this function will return 0.
 */
interval_t reliable_send_timeout (const struct send_reliable *rel);

void reliable_debug_print (const struct send_reliable *rel, char *desc);

/* set sending timeout (after this time we send again until ACK) */
static inline void
reliable_set_timeout (struct send_reliable *rel, interval_t timeout)
{
  rel->initial_timeout = timeout;
}

/* print a reliable ACK record coming off the wire */
const char *reliable_ack_print (struct buffer *buf, bool verbose, struct gc_arena *gc);

void reliable_ack_debug_print (const struct reliable_ack *ack, char *desc);

/** @} name Miscellaneous functions */


/** @} addtogroup reliable */


#endif /* RELIABLE_H */
#endif /* ENABLE_CRYPTO && ENABLE_SSL */
