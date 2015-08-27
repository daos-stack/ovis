/*
 * Copyright (c) 2010 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2010 Sandia Corporation. All rights reserved.
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the U.S. Government.
 * Export of this program may require a license from the United States
 * Government.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of Sandia nor the names of any contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *      Neither the name of Open Grid Computing nor the names of any
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *      Modified source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Author: Narate Taerat <narate@ogc.us>
 */
#ifndef __LDMS_XPRT_SOCK_H__
#define __LDMS_XPRT_SOCK_H__
#include <semaphore.h>
#include <sys/queue.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/thread.h>

#include "coll/rbt.h"
#include "zap.h"
#include "zap_priv.h"

/**
 * \brief Value for TCP_KEEPIDLE option for initiator side socket.
 *
 * This will make Linux send 'keep alive' probe when the socket being idle for
 * 10 seconds (only for initiator side zap connections).
 *
 * \note Default value of TCP_KEEPIDLE is 7200 sec = 2 hrs
 */
#define ZAP_SOCK_KEEPIDLE 10

/**
 * \brief Value for TCP_KEEPCNT option for initiator side socket.
 *
 * For this setting, a connection will be dropped after 3 probes.
 *
 * \note Default TCP_KEEPCNT is 9
 */
#define ZAP_SOCK_KEEPCNT 3

/**
 * \brief Value for TCP_KEEPINTVL option for initiator side socket.
 *
 * This is a time between probes after idle (set to 2 seconds).
 *
 * \note Default TCP_KEEPINTVL is 75 seconds
 */
#define ZAP_SOCK_KEEPINTVL 2

struct zap_sock_map {
	struct zap_map map;
	uint32_t key; /**< Key of the map. */
};

struct z_sock_key {
	struct rbn rb_node;
	struct zap_sock_map *map; /**< reference to zap_map */
};

typedef enum sock_msg_type {
	SOCK_MSG_SENDRECV = 1,/*  send-receive  */
	SOCK_MSG_CONNECT,     /*  Connect     data          */
	SOCK_MSG_RENDEZVOUS,  /*  Share       zap_map       */
	SOCK_MSG_READ_REQ,    /*  Read        request       */
	SOCK_MSG_READ_RESP,   /*  Read        response      */
	SOCK_MSG_WRITE_REQ,   /*  Write       request       */
	SOCK_MSG_WRITE_RESP,  /*  Write       response      */
	SOCK_MSG_ACCEPTED,    /*  Connection  accepted      */
	SOCK_MSG_TYPE_LAST
} sock_msg_type_t;;

static const char *__sock_msg_type_str[] = {
	[0]     =  "SOCK_MSG_INVALID",
	[SOCK_MSG_SENDRECV]    =  "SOCK_MSG_SENDRECV",
	[SOCK_MSG_CONNECT]     =  "SOCK_MSG_CONNECT",
	[SOCK_MSG_RENDEZVOUS]  =  "SOCK_MSG_RENDEZVOUS",
	[SOCK_MSG_READ_REQ]    =  "SOCK_MSG_READ_REQ",
	[SOCK_MSG_READ_RESP]   =  "SOCK_MSG_READ_RESP",
	[SOCK_MSG_WRITE_REQ]   =  "SOCK_MSG_WRITE_REQ",
	[SOCK_MSG_WRITE_RESP]  =  "SOCK_MSG_WRITE_RESP",
	[SOCK_MSG_ACCEPTED]    =  "SOCK_MSG_ACCEPTED",
};

#pragma pack(4)

/**
 * \brief Zap message header for socket transport.
 *
 * Each of the sock_msg's is an extension to ::sock_msg_hdr.
 */
struct sock_msg_hdr {
	uint16_t msg_type; /**< The request type */
	uint32_t msg_len;  /**< Length of the entire message, header included. */
	uint32_t xid;	   /**< Transaction Id to check against reply */
	uint64_t ctxt;	   /**< User context to be returned in reply */
};

static char ZAP_SOCK_SIG[8] = "SOCKET";

/**
 * Connect message.
 */
struct sock_msg_connect {
	struct sock_msg_hdr hdr;
	struct zap_version ver;
	char sig[8];
	uint32_t data_len;
	char data[0];
};

/**
 * Send/Recv message.
 */
struct sock_msg_sendrecv {
	struct sock_msg_hdr hdr;
	uint32_t data_len;
	char data[0];
};

/**
 * Read request (src_addr --> dst_addr)
 */
struct sock_msg_read_req {
	struct sock_msg_hdr hdr;
	uint32_t src_map_key; /**< Source map reference (on non-initiator) */
	uint64_t src_ptr; /**< Source memory */
	uint32_t data_len; /**< Data length */
};

/**
 * Read response
 */
struct sock_msg_read_resp {
	struct sock_msg_hdr hdr;
	uint16_t status; /**< Return status */
	uint64_t dst_ptr; /**< Destination memory addr (on initiator) */
	uint32_t data_len; /**< Response data length */
	char data[0]; /**< Response data */
};

/**
 * Write request
 */
struct sock_msg_write_req {
	struct sock_msg_hdr hdr;
	uint32_t dst_map_key; /**< Destination map key */
	uint64_t dst_ptr; /**< Destination address */
	uint32_t data_len; /**< Data length */
	char data[0]; /**< data for SOCK_MSG_WRITE_REQ */
};

/**
 * Write response
 */
struct sock_msg_write_resp {
	struct sock_msg_hdr hdr;
	uint16_t status; /**< Return status */
};

/**
 * Message for exporting/sharing zap_map.
 */
struct sock_msg_rendezvous {
	struct sock_msg_hdr hdr;
	uint32_t rmap_key; /**< Remote map reference */
	uint32_t acc; /**< Access */
	uint64_t addr; /**< Address in the map */
	uint32_t data_len; /**< Length */
	char msg[0]; /**< Context */
};

/**
 * Keeps track of outstanding I/O so that it can be cleaned up when
 * the endpoint shuts down. A z_sock_io is either on the free_q or the
 * io_q for the endpoint.
 */
struct z_sock_io {
	TAILQ_ENTRY(z_sock_io) q_link;
	zap_map_t dst_map; /**< Destination map for RDMA_READ */
	char *dst_ptr; /**< Destination address for RDMA_READ */
	union {
		struct sock_msg_hdr hdr;
		struct sock_msg_read_req read;
		struct sock_msg_write_req write;
	};
};

#pragma pack()

struct z_sock_ep {
	struct zap_ep ep;

	int sock;
	struct bufferevent *buf_event;
	struct evconnlistener *listen_ev;
	char *conn_data;
	size_t conn_data_len;

	pthread_mutex_t q_lock;
	TAILQ_HEAD(z_sock_free_q, z_sock_io) free_q;
	TAILQ_HEAD(z_sock_io_q, z_sock_io) io_q;
	LIST_ENTRY(z_sock_ep) link;
};

static inline struct z_sock_ep *z_sock_from_ep(zap_ep_t *ep)
{
	return (struct z_sock_ep *)ep;
}

#endif
