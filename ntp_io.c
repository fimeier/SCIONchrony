/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Richard P. Curnow  1997-2003
 * Copyright (C) Timo Teras  2009
 * Copyright (C) Miroslav Lichvar  2009, 2013-2016, 2018-2020
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 **********************************************************************

  =======================================================================

  This file deals with the IO aspects of reading and writing NTP packets
  */

#include "config.h"

#include "sysincl.h"

#include "ntp_io.h"
#include "ntp_core.h"
#include "ntp_sources.h"
#include "sched.h"
#include "socket.h"
#include "local.h"
#include "logging.h"
#include "conf.h"
#include "privops.h"
#include "util.h"

#ifdef HAVE_LINUX_TIMESTAMPING
#include "ntp_io_linux.h"
#endif

#define INVALID_SOCK_FD -1

/* The server/peer and client sockets for IPv4 and IPv6 */
static int server_sock_fd4;
static int server_sock_fd6;
static int client_sock_fd4;
static int client_sock_fd6;

/* Reference counters for server sockets to keep them open only when needed */
static int server_sock_ref4;
static int server_sock_ref6;

/* Flag indicating we create a new connected client socket for each
   server instead of sharing client_sock_fd4 and client_sock_fd6 */
static int separate_client_sockets;

/* Flag indicating the server sockets are not created dynamically when needed,
   either to have a socket for client requests when separate client sockets
   are disabled and client port is equal to server port, or the server port is
   disabled */
static int permanent_server_sockets;

/* Flag indicating the server IPv4 socket is bound to an address */
static int bound_server_sock_fd4;

/* Flag indicating that we have been initialised */
static int initialised=0;

/* ================================================== */

/* Forward prototypes */
static void read_from_socket(int sock_fd, int event, void *anything);

/* ================================================== */

static int
open_socket(int family, int local_port, int client_only, IPSockAddr *remote_addr)
{
  int sock_fd, sock_flags, dscp, events = SCH_FILE_INPUT;
  IPSockAddr local_addr;
  char *iface;

  if (!SCK_IsIpFamilyEnabled(family))
    return INVALID_SOCK_FD;

  if (!client_only) {
    CNF_GetBindAddress(family, &local_addr.ip_addr);
    iface = CNF_GetBindNtpInterface();
  } else {
    CNF_GetBindAcquisitionAddress(family, &local_addr.ip_addr);
    iface = CNF_GetBindAcquisitionInterface(); //mefi84 erlaubt client socket auf spezifisches device zu binden https://chrony.tuxfamily.org/doc/4.0/chrony.conf.html#bindacqdevice
  }

  local_addr.port = local_port;

  sock_flags = SCK_FLAG_RX_DEST_ADDR | SCK_FLAG_PRIV_BIND; //mefi84 unklar was diese Flags sollen..insbesondere die Anwendung in open_ip_socket()::open_socket() etc... WIRD missbraucht: Zusätzliche Funktionen werten diese Parameter aus und setzten dann die korrekten Flags gemäss man7.org ;-)
  if (!client_only)
    sock_flags |= SCK_FLAG_BROADCAST;

  sock_fd = SCK_OpenUdpSocket(remote_addr, &local_addr, iface, sock_flags); //mefi84 zB für CNF_SetupAddessRestrictions ie open server port: sudo lsof -n -P | grep ":123"
  if (sock_fd < 0) {
    if (!client_only)
      LOG(LOGS_ERR, "Could not open NTP socket on %s", UTI_IPSockAddrToString(&local_addr));
    return INVALID_SOCK_FD;
  }

  dscp = CNF_GetNtpDscp(); //mefi84 https://chrony.tuxfamily.org/doc/4.0/chrony.conf.html#dscp
  if (dscp > 0 && dscp < 64) {
#ifdef IP_TOS
    if (!SCK_SetIntOption(sock_fd, IPPROTO_IP, IP_TOS, dscp << 2))
      ;
#endif
  }

  if (!client_only && family == IPADDR_INET4 && local_addr.port > 0)
    bound_server_sock_fd4 = local_addr.ip_addr.addr.in4 != INADDR_ANY;

  /* Enable kernel/HW timestamping of packets */
#ifdef HAVE_LINUX_TIMESTAMPING
  if (!NIO_Linux_SetTimestampSocketOptions(sock_fd, client_only, &events)) //mefi84 (bsp Komm mit NTPServer) aktiviert Flags und fügt event SCH_FILE_EXCEPTION hinzu (vermutlich um TS per err-queue zu lesen)
#endif
    if (!SCK_EnableKernelRxTimestamping(sock_fd))
      ;

  /* Register handler for read and possibly exception events on the socket */
  SCH_AddFileHandler(sock_fd, events, read_from_socket, NULL);

  return sock_fd;
}

/* ================================================== */

static int
open_separate_client_socket(IPSockAddr *remote_addr) //mefi84 SCIONCHANGE needed
{
  return open_socket(remote_addr->ip_addr.family, 0, 1, remote_addr);
}

/* ================================================== */

static void
close_socket(int sock_fd)
{
  if (sock_fd == INVALID_SOCK_FD)
    return;

#ifdef HAVE_LINUX_TIMESTAMPING
  NIO_Linux_NotifySocketClosing(sock_fd);
#endif
  SCH_RemoveFileHandler(sock_fd);
  SCK_CloseSocket(sock_fd);
}

/* ================================================== */

void
NIO_Initialise(void)
{
  int server_port, client_port;

  assert(!initialised);
  initialised = 1;

#ifdef PRIVOPS_BINDSOCKET
  SCK_SetPrivBind(PRV_BindSocket);
#endif

#ifdef HAVE_LINUX_TIMESTAMPING
  NIO_Linux_Initialise();
#else
  if (1) {
    CNF_HwTsInterface *conf_iface;
    if (CNF_GetHwTsInterface(0, &conf_iface))
      LOG_FATAL("HW timestamping not supported");
  }
#endif

  server_port = CNF_GetNTPPort();
  client_port = CNF_GetAcquisitionPort();

  /* Use separate connected sockets if client port is negative */
  separate_client_sockets = client_port < 0;
  if (client_port < 0)
    client_port = 0;

  permanent_server_sockets = !server_port || (!separate_client_sockets &&
                                              client_port == server_port);

  server_sock_fd4 = INVALID_SOCK_FD;
  server_sock_fd6 = INVALID_SOCK_FD;
  client_sock_fd4 = INVALID_SOCK_FD;
  client_sock_fd6 = INVALID_SOCK_FD;
  server_sock_ref4 = 0;
  server_sock_ref6 = 0;

  if (permanent_server_sockets && server_port) {
    server_sock_fd4 = open_socket(IPADDR_INET4, server_port, 0, NULL);
    server_sock_fd6 = open_socket(IPADDR_INET6, server_port, 0, NULL);
  }

  if (!separate_client_sockets) {
    if (client_port != server_port || !server_port) {
      client_sock_fd4 = open_socket(IPADDR_INET4, client_port, 1, NULL);
      client_sock_fd6 = open_socket(IPADDR_INET6, client_port, 1, NULL);
    } else {
      client_sock_fd4 = server_sock_fd4;
      client_sock_fd6 = server_sock_fd6;
    }
  }

  if ((server_port && permanent_server_sockets &&
       server_sock_fd4 == INVALID_SOCK_FD && server_sock_fd6 == INVALID_SOCK_FD) ||
      (!separate_client_sockets &&
       client_sock_fd4 == INVALID_SOCK_FD && client_sock_fd6 == INVALID_SOCK_FD)) {
    LOG_FATAL("Could not open NTP sockets");
  }
}

/* ================================================== */

void
NIO_Finalise(void)
{
  if (server_sock_fd4 != client_sock_fd4)
    close_socket(client_sock_fd4);
  close_socket(server_sock_fd4);
  server_sock_fd4 = client_sock_fd4 = INVALID_SOCK_FD;

  if (server_sock_fd6 != client_sock_fd6)
    close_socket(client_sock_fd6);
  close_socket(server_sock_fd6);
  server_sock_fd6 = client_sock_fd6 = INVALID_SOCK_FD;

#ifdef HAVE_LINUX_TIMESTAMPING
  NIO_Linux_Finalise();
#endif

  initialised = 0;
}

/* ================================================== */

int
NIO_OpenClientSocket(NTP_Remote_Address *remote_addr) //mefi84 SCION anpassung nötig
{
  if (separate_client_sockets) {
    return open_separate_client_socket(remote_addr);
  } else {
    switch (remote_addr->ip_addr.family) {
      case IPADDR_INET4:
        return client_sock_fd4;
      case IPADDR_INET6:
        return client_sock_fd6;
      default:
        return INVALID_SOCK_FD;
    }
  }
}

/* ================================================== */

int
NIO_OpenServerSocket(NTP_Remote_Address *remote_addr)
{
  switch (remote_addr->ip_addr.family) {
    case IPADDR_INET4:
      if (permanent_server_sockets)
        return server_sock_fd4;
      if (server_sock_fd4 == INVALID_SOCK_FD)
        server_sock_fd4 = open_socket(IPADDR_INET4, CNF_GetNTPPort(), 0, NULL);
      if (server_sock_fd4 != INVALID_SOCK_FD)
        server_sock_ref4++;
      return server_sock_fd4;
    case IPADDR_INET6:
      if (permanent_server_sockets)
        return server_sock_fd6;
      if (server_sock_fd6 == INVALID_SOCK_FD)
        server_sock_fd6 = open_socket(IPADDR_INET6, CNF_GetNTPPort(), 0, NULL);
      if (server_sock_fd6 != INVALID_SOCK_FD)
        server_sock_ref6++;
      return server_sock_fd6;
    default:
      return INVALID_SOCK_FD;
  }
}

/* ================================================== */

void
NIO_CloseClientSocket(int sock_fd)
{
  if (separate_client_sockets)
    close_socket(sock_fd);
}

/* ================================================== */

void
NIO_CloseServerSocket(int sock_fd)
{
  if (permanent_server_sockets || sock_fd == INVALID_SOCK_FD)
    return;

  if (sock_fd == server_sock_fd4) {
    if (--server_sock_ref4 <= 0) {
      close_socket(server_sock_fd4);
      server_sock_fd4 = INVALID_SOCK_FD;
    }
  } else if (sock_fd == server_sock_fd6) {
    if (--server_sock_ref6 <= 0) {
      close_socket(server_sock_fd6);
      server_sock_fd6 = INVALID_SOCK_FD;
    }
  } else {
    assert(0);
  }
}

/* ================================================== */

int
NIO_IsServerSocket(int sock_fd)
{
  return sock_fd != INVALID_SOCK_FD &&
    (sock_fd == server_sock_fd4 || sock_fd == server_sock_fd6);
}

/* ================================================== */

int
NIO_IsServerSocketOpen(void)
{
  return server_sock_fd4 != INVALID_SOCK_FD || server_sock_fd6 != INVALID_SOCK_FD;
}

/* ================================================== */

int
NIO_IsServerConnectable(NTP_Remote_Address *remote_addr)
{
  int sock_fd;

  sock_fd = open_separate_client_socket(remote_addr);
  if (sock_fd == INVALID_SOCK_FD)
    return 0;

  close_socket(sock_fd);

  return 1;
}

/* ================================================== */

static void
process_message(SCK_Message *message, int sock_fd, int event)
{
  NTP_Local_Address local_addr;
  NTP_Local_Timestamp local_ts;
  struct timespec sched_ts;

  SCH_GetLastEventTime(&local_ts.ts, &local_ts.err, NULL);
  local_ts.source = NTP_TS_DAEMON;
  sched_ts = local_ts.ts;

  if (message->addr_type != SCK_ADDR_IP) {
    DEBUG_LOG("Unexpected address type");
    return;
  }

  local_addr.ip_addr = message->local_addr.ip;
  local_addr.if_index = message->if_index;;
  local_addr.sock_fd = sock_fd;

#ifdef HAVE_LINUX_TIMESTAMPING
  if (NIO_Linux_ProcessMessage(message, &local_addr, &local_ts, event))
    return; //mefi84 TX bricht hier immer ab
#else
  if (!UTI_IsZeroTimespec(&message->timestamp.kernel)) {
    LCL_CookTime(&message->timestamp.kernel, &local_ts.ts, &local_ts.err);
    local_ts.source = NTP_TS_KERNEL;
  }
#endif

  if (local_ts.source != NTP_TS_DAEMON)
    DEBUG_LOG("Updated RX timestamp delay=%.9f tss=%u",
              UTI_DiffTimespecsToDouble(&sched_ts, &local_ts.ts), local_ts.source);

  /* Just ignore the packet if it's not of a recognized length */
  if (message->length < NTP_HEADER_LENGTH || message->length > sizeof (NTP_Packet)) {
    DEBUG_LOG("Unexpected length");
    return;
  }

  NSR_ProcessRx(&message->remote_addr.ip, &local_addr, &local_ts, message->data, message->length);
}

/* ================================================== */

static void
read_from_socket(int sock_fd, int event, void *anything)
{
  SCK_Message *messages;
  int i, received, flags = 0;

#ifdef HAVE_LINUX_TIMESTAMPING
  if (NIO_Linux_ProcessEvent(sock_fd, event))
    return;
#endif

  if (event == SCH_FILE_EXCEPTION) {
#ifdef HAVE_LINUX_TIMESTAMPING
    flags |= SCK_FLAG_MSG_ERRQUEUE;
#else
    assert(0);
#endif
  }

  messages = SCK_ReceiveMessages(sock_fd, flags, &received);
  if (!messages)
    return;

  for (i = 0; i < received; i++)
    process_message(&messages[i], sock_fd, event);
}

/* ================================================== */
/* Send a packet to remote address from local address */

int
NIO_SendPacket(NTP_Packet *packet, NTP_Remote_Address *remote_addr,
               NTP_Local_Address *local_addr, int length, int process_tx)
{
  SCK_Message message;

  assert(initialised);

  if (local_addr->sock_fd == INVALID_SOCK_FD) {
    DEBUG_LOG("No socket to send to %s", UTI_IPSockAddrToString(remote_addr));
    return 0;
  }

  SCK_InitMessage(&message, SCK_ADDR_IP); //mefi84 setzt alle 0

  message.data = packet;
  message.length = length;

  /* Specify remote address if the socket is not connected */
  if (NIO_IsServerSocket(local_addr->sock_fd) || !separate_client_sockets) {
    message.remote_addr.ip.ip_addr = remote_addr->ip_addr;
    message.remote_addr.ip.port = remote_addr->port;
  }

  message.local_addr.ip = local_addr->ip_addr; //mefi84 warum steht hier crap drin? Wird nicht gesetzt in transmit_timeout->transmit_packet->NIOSendPacket OK wenn family=IPADDR_UNSPEC

  /* Don't require responses to non-link-local addresses to use the same
     interface */
  message.if_index = SCK_IsLinkLocalIPAddress(&message.remote_addr.ip.ip_addr) ?
                       local_addr->if_index : INVALID_IF_INDEX;

#if !defined(HAVE_IN_PKTINFO) && defined(IP_SENDSRCADDR)
  /* On FreeBSD a local IPv4 address cannot be specified on bound socket */
  if (message.local_addr.ip.family == IPADDR_INET4 &&
      (local_addr->sock_fd != server_sock_fd4 || bound_server_sock_fd4))
    message.local_addr.ip.family = IPADDR_UNSPEC;
#endif

#ifdef HAVE_LINUX_TIMESTAMPING
  if (process_tx)
    NIO_Linux_RequestTxTimestamp(&message, local_addr->sock_fd); //mefi84 irreführend: Für Clients setzt es monitored_socket = sock_fd um auf HW TS zu warten
#endif

  if (!SCK_SendMessage(local_addr->sock_fd, &message, 0))
    return 0;

  return 1;
}
