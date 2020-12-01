/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2016-2019
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

  Functions for NTP I/O specific to Linux
  */

#include "config.h"

#include "sysincl.h"

#include <ifaddrs.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>

#include "array.h"
#include "conf.h"
#include "hwclock.h"
#include "local.h"
#include "logging.h"
#include "ntp_core.h"
#include "ntp_io.h"
#include "ntp_io_linux.h"
#include "ntp_sources.h"
#include "sched.h"
#include "socket.h"
#include "sys_linux.h"
#include "util.h"

struct Interface {
  char name[IF_NAMESIZE];
  int if_index;
  int phc_fd;
  int phc_mode;
  int phc_nocrossts;
  /* Link speed in mbit/s */
  int link_speed;
  /* Start of UDP data at layer 2 for IPv4 and IPv6 */
  int l2_udp4_ntp_start;
  int l2_udp6_ntp_start;
  /* Precision of PHC readings */
  double precision;
  /* Compensation of errors in TX and RX timestamping */
  double tx_comp;
  double rx_comp;
  HCL_Instance clock;
};

/* Number of PHC readings per HW clock sample */
#define PHC_READINGS 10

/* Minimum interval between PHC readings */
#define MIN_PHC_POLL -6

/* Maximum acceptable offset between HW and daemon/kernel timestamp */
#define MAX_TS_DELAY 1.0

/* Array of Interfaces */
static ARR_Instance interfaces;

/* RX/TX and TX-specific timestamping socket options */
static int ts_flags;
static int ts_tx_flags;

/* Flag indicating the socket options can't be changed in control messages */
static int permanent_ts_options;

/* When sending client requests to a close and fast server, it is possible that
   a response will be received before the HW transmit timestamp of the request
   itself.  To avoid processing of the response without the HW timestamp, we
   monitor events returned by select() and suspend reading of packets from the
   receive queue for up to 200 microseconds.  As the requests are normally
   separated by at least 200 milliseconds, it is sufficient to monitor and
   suspend one socket at a time. */
static int monitored_socket;
static int suspended_socket;
static SCH_TimeoutID resume_timeout_id;

#define RESUME_TIMEOUT 200.0e-6

/* Unbound socket keeping the kernel RX timestamping permanently enabled
   in order to avoid a race condition between receiving a server response
   and the kernel actually starting to timestamp received packets after
   enabling the timestamping and sending a request */
static int dummy_rxts_socket;

#define INVALID_SOCK_FD -3

/* ================================================== */

static int
add_interface(CNF_HwTsInterface *conf_iface) //mefi84 NIC: 1. Get ts_info 2. Get it's "PHC" i.e. /dev/ptp0 and register it as interface HINT: iface{IN}interfaces ist static i.e. permanent storage
{
  struct ethtool_ts_info ts_info;
  struct hwtstamp_config ts_config;
  struct ifreq req;
  int sock_fd, if_index, phc_fd, req_hwts_flags, rx_filter;
  unsigned int i;
  struct Interface *iface;

  /* Check if the interface was not already added */
  for (i = 0; i < ARR_GetSize(interfaces); i++) {
    if (!strcmp(conf_iface->name, ((struct Interface *)ARR_GetElement(interfaces, i))->name))
      return 1;
  }

  sock_fd = SCK_OpenUdpSocket(NULL, NULL, NULL, 0);
  if (sock_fd < 0)
    return 0;

  memset(&req, 0, sizeof (req));
  memset(&ts_info, 0, sizeof (ts_info));

  if (snprintf(req.ifr_name, sizeof (req.ifr_name), "%s", conf_iface->name) >=
      sizeof (req.ifr_name)) {
    SCK_CloseSocket(sock_fd);
    return 0;
  }

  if (ioctl(sock_fd, SIOCGIFINDEX, &req)) {
    DEBUG_LOG("ioctl(%s) failed : %s", "SIOCGIFINDEX", strerror(errno));
    SCK_CloseSocket(sock_fd);
    return 0;
  }

  if_index = req.ifr_ifindex;

  ts_info.cmd = ETHTOOL_GET_TS_INFO; //mefi84 TS Flags Abfrage vorbereiten
  req.ifr_data = (char *)&ts_info;

  if (ioctl(sock_fd, SIOCETHTOOL, &req)) { //mefi84 TS Flags Abfrage ausführen
    DEBUG_LOG("ioctl(%s) failed : %s", "SIOCETHTOOL", strerror(errno));
    SCK_CloseSocket(sock_fd);
    return 0;
  }

  req_hwts_flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_TX_HARDWARE | //mefi84 TS Flags vergleichen mit gewünschtem
                   SOF_TIMESTAMPING_RAW_HARDWARE;
  if ((ts_info.so_timestamping & req_hwts_flags) != req_hwts_flags) {
    DEBUG_LOG("HW timestamping not supported on %s", req.ifr_name);
    SCK_CloseSocket(sock_fd);
    return 0;
  }

  if (ts_info.phc_index < 0) {
    DEBUG_LOG("PHC missing on %s", req.ifr_name);
    SCK_CloseSocket(sock_fd);
    return 0;
  }

  switch (conf_iface->rxfilter) {
    case CNF_HWTS_RXFILTER_ANY:
#ifdef HAVE_LINUX_TIMESTAMPING_RXFILTER_NTP
      if (ts_info.rx_filters & (1 << HWTSTAMP_FILTER_NTP_ALL))
        rx_filter = HWTSTAMP_FILTER_NTP_ALL;
      else
#endif
      if (ts_info.rx_filters & (1 << HWTSTAMP_FILTER_ALL))
        rx_filter = HWTSTAMP_FILTER_ALL;
      else
        rx_filter = HWTSTAMP_FILTER_NONE;
      break;
    case CNF_HWTS_RXFILTER_NONE:
      rx_filter = HWTSTAMP_FILTER_NONE;
      break;
#ifdef HAVE_LINUX_TIMESTAMPING_RXFILTER_NTP
    case CNF_HWTS_RXFILTER_NTP:
      rx_filter = HWTSTAMP_FILTER_NTP_ALL;
      break;
#endif
    default:
      rx_filter = HWTSTAMP_FILTER_ALL;
      break;
  }

  ts_config.flags = 0; //mefi84 activate HWTSTAMP with supported types/filters
  ts_config.tx_type = HWTSTAMP_TX_ON;
  ts_config.rx_filter = rx_filter;
  req.ifr_data = (char *)&ts_config;

  if (ioctl(sock_fd, SIOCSHWTSTAMP, &req)) { //mefi84 optionen effektiv aktivieren, returns 0 if succ
    LOG(errno == EPERM ? LOGS_ERR : LOGS_DEBUG,
        "ioctl(%s) failed : %s", "SIOCSHWTSTAMP", strerror(errno));

    /* Check the current timestamping configuration in case this interface
       allows only reading of the configuration and it was already configured
       as requested */
    req.ifr_data = (char *)&ts_config;
#ifdef SIOCGHWTSTAMP
    if (ioctl(sock_fd, SIOCGHWTSTAMP, &req) ||
        ts_config.tx_type != HWTSTAMP_TX_ON || ts_config.rx_filter != rx_filter)
#endif
    {
      SCK_CloseSocket(sock_fd);
      return 0;
    }
  }

  SCK_CloseSocket(sock_fd);

  phc_fd = SYS_Linux_OpenPHC(NULL, ts_info.phc_index);
  if (phc_fd < 0)
    return 0;

  iface = ARR_GetNewElement(interfaces);

  snprintf(iface->name, sizeof (iface->name), "%s", conf_iface->name);
  iface->if_index = if_index;
  iface->phc_fd = phc_fd;
  iface->phc_mode = 0;
  iface->phc_nocrossts = conf_iface->nocrossts;

  /* Start with 1 gbit and no VLANs or IPv4/IPv6 options */
  iface->link_speed = 1000;
  iface->l2_udp4_ntp_start = 42;
  iface->l2_udp6_ntp_start = 62;

  iface->precision = conf_iface->precision;
  iface->tx_comp = conf_iface->tx_comp;
  iface->rx_comp = conf_iface->rx_comp;

  iface->clock = HCL_CreateInstance(conf_iface->min_samples, conf_iface->max_samples,
                                    UTI_Log2ToDouble(MAX(conf_iface->minpoll, MIN_PHC_POLL)));

  LOG(LOGS_INFO, "Enabled HW timestamping %son %s",
      ts_config.rx_filter == HWTSTAMP_FILTER_NONE ? "(TX only) " : "", iface->name);

  return 1;
}

/* ================================================== */

static int
add_all_interfaces(CNF_HwTsInterface *conf_iface_all)
{
  CNF_HwTsInterface conf_iface;
  struct ifaddrs *ifaddr, *ifa;
  int r;

  conf_iface = *conf_iface_all;

  if (getifaddrs(&ifaddr)) {
    DEBUG_LOG("getifaddrs() failed : %s", strerror(errno));
    return 0;
  }

  for (r = 0, ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    conf_iface.name = ifa->ifa_name;
    if (add_interface(&conf_iface))
      r = 1;
  }
  
  freeifaddrs(ifaddr);

  /* Return success if at least one interface was added */
  return r;
}

/* ================================================== */

static void
update_interface_speed(struct Interface *iface)
{
  struct ethtool_cmd cmd;
  struct ifreq req;
  int sock_fd, link_speed;

  sock_fd = SCK_OpenUdpSocket(NULL, NULL, NULL, 0);
  if (sock_fd < 0)
    return;

  memset(&req, 0, sizeof (req));
  memset(&cmd, 0, sizeof (cmd));

  snprintf(req.ifr_name, sizeof (req.ifr_name), "%s", iface->name);
  cmd.cmd = ETHTOOL_GSET;
  req.ifr_data = (char *)&cmd;

  if (ioctl(sock_fd, SIOCETHTOOL, &req)) {
    DEBUG_LOG("ioctl(%s) failed : %s", "SIOCETHTOOL", strerror(errno));
    SCK_CloseSocket(sock_fd);
    return;
  }

  SCK_CloseSocket(sock_fd);

  link_speed = ethtool_cmd_speed(&cmd);

  if (iface->link_speed != link_speed) {
    iface->link_speed = link_speed;
    DEBUG_LOG("Updated speed of %s to %d Mb/s", iface->name, link_speed);
  }
}

/* ================================================== */

#if defined(HAVE_LINUX_TIMESTAMPING_OPT_PKTINFO) || defined(HAVE_LINUX_TIMESTAMPING_OPT_TX_SWHW)
static int
check_timestamping_option(int option)
{
  int sock_fd;

  sock_fd = SCK_OpenUdpSocket(NULL, NULL, NULL, 0);
  if (sock_fd < 0)
    return 0;

  if (!SCK_SetIntOption(sock_fd, SOL_SOCKET, SO_TIMESTAMPING, option)) {
    SCK_CloseSocket(sock_fd);
    return 0;
  }

  SCK_CloseSocket(sock_fd);
  return 1;
}
#endif

/* ================================================== */

static int
open_dummy_socket(void)
{
  int sock_fd, events = 0;

  sock_fd = SCK_OpenUdpSocket(NULL, NULL, NULL, 0);
  if (sock_fd < 0)
    return INVALID_SOCK_FD;

  if (!NIO_Linux_SetTimestampSocketOptions(sock_fd, 1, &events)) {
    SCK_CloseSocket(sock_fd);
    return INVALID_SOCK_FD;
  }

  return sock_fd;
}

/* ================================================== */

void
NIO_Linux_Initialise(void)
{
  CNF_HwTsInterface *conf_iface;
  unsigned int i;
  int hwts;

  interfaces = ARR_CreateInstance(sizeof (struct Interface));

  /* Enable HW timestamping on specified interfaces.  If "*" was specified, try
     all interfaces.  If no interface was specified, enable SW timestamping. */

  for (i = hwts = 0; CNF_GetHwTsInterface(i, &conf_iface); i++) {
    if (!strcmp("*", conf_iface->name))
      continue;
    if (!add_interface(conf_iface)) //mefi84 fügt für ausgewählte NICs PHC interface (PTP) hinzu, d.h. HW-CLock im NIC
      LOG_FATAL("Could not enable HW timestamping on %s", conf_iface->name);
    hwts = 1;
  }

  for (i = 0; CNF_GetHwTsInterface(i, &conf_iface); i++) {
    if (strcmp("*", conf_iface->name))
      continue;
    if (add_all_interfaces(conf_iface))
      hwts = 1;
    break;
  }
  
  ts_flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE; 
  ts_tx_flags = SOF_TIMESTAMPING_TX_SOFTWARE;
  //mefi84 flags werden bei add_interface() bereits geprüft im Context des ausgewählten "NIC"... check_timestamping_option() scheinen HW unabhängig zu sein, da NIC nicht gewählt wird
  if (hwts) {
    ts_flags |= SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE;
    ts_tx_flags |= SOF_TIMESTAMPING_TX_HARDWARE;
#ifdef HAVE_LINUX_TIMESTAMPING_OPT_PKTINFO
    if (check_timestamping_option(SOF_TIMESTAMPING_OPT_PKTINFO))
      ts_flags |= SOF_TIMESTAMPING_OPT_PKTINFO;
#endif
#ifdef HAVE_LINUX_TIMESTAMPING_OPT_TX_SWHW
    if (check_timestamping_option(SOF_TIMESTAMPING_OPT_TX_SWHW))
      ts_flags |= SOF_TIMESTAMPING_OPT_TX_SWHW;
#endif
  }

  /* Enable IP_PKTINFO in messages looped back to the error queue */
  ts_flags |= SOF_TIMESTAMPING_OPT_CMSG;

  /* Kernels before 4.7 ignore timestamping flags set in control messages */
  permanent_ts_options = !SYS_Linux_CheckKernelVersion(4, 7);

  monitored_socket = INVALID_SOCK_FD; //mefi84 ????...
  suspended_socket = INVALID_SOCK_FD;
  dummy_rxts_socket = INVALID_SOCK_FD;
}

/* ================================================== */

void
NIO_Linux_Finalise(void)
{
  struct Interface *iface;
  unsigned int i;

  if (dummy_rxts_socket != INVALID_SOCK_FD)
    SCK_CloseSocket(dummy_rxts_socket);

  for (i = 0; i < ARR_GetSize(interfaces); i++) {
    iface = ARR_GetElement(interfaces, i);
    HCL_DestroyInstance(iface->clock);
    close(iface->phc_fd);
  }

  ARR_DestroyInstance(interfaces);
}

/* ================================================== */

int
NIO_Linux_SetTimestampSocketOptions(int sock_fd, int client_only, int *events)
{
  int val, flags;

  if (!ts_flags)
    return 0;

  /* Enable SCM_TIMESTAMPING control messages and the socket's error queue in
     order to receive our transmitted packets with more accurate timestamps */

  val = 1;
  flags = ts_flags;

  if (client_only || permanent_ts_options)
    flags |= ts_tx_flags;

  if (!SCK_SetIntOption(sock_fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE, val)) {
    ts_flags = 0;
    return 0;
  }

  if (!SCK_SetIntOption(sock_fd, SOL_SOCKET, SO_TIMESTAMPING, flags)) {
    ts_flags = 0;
    return 0;
  }

  *events |= SCH_FILE_EXCEPTION;
  return 1;
}

/* ================================================== */

static void
resume_socket(int sock_fd)
{
  if (monitored_socket == sock_fd)
    monitored_socket = INVALID_SOCK_FD;

  if (sock_fd == INVALID_SOCK_FD || sock_fd != suspended_socket)
    return;

  suspended_socket = INVALID_SOCK_FD;

  SCH_SetFileHandlerEvent(sock_fd, SCH_FILE_INPUT, 1);

  DEBUG_LOG("Resumed RX processing %s timeout fd=%d",
            resume_timeout_id ? "before" : "on", sock_fd);

  if (resume_timeout_id) {
    SCH_RemoveTimeout(resume_timeout_id);
    resume_timeout_id = 0;
  }
}

/* ================================================== */

static void
resume_timeout(void *arg)
{
  resume_timeout_id = 0;
  resume_socket(suspended_socket);
}

/* ================================================== */

static void
suspend_socket(int sock_fd)
{
  resume_socket(suspended_socket);

  suspended_socket = sock_fd;

  SCH_SetFileHandlerEvent(suspended_socket, SCH_FILE_INPUT, 0);
  resume_timeout_id = SCH_AddTimeoutByDelay(RESUME_TIMEOUT, resume_timeout, NULL);

  DEBUG_LOG("Suspended RX processing fd=%d", sock_fd);
}

/* ================================================== */

int
NIO_Linux_ProcessEvent(int sock_fd, int event)
{
  if (sock_fd != monitored_socket) //mefi84 Race-Condition oder nur Debuggin problem?? Schlägt fehl, wenn überschrieben wurde
    return 0;

  if (event == SCH_FILE_INPUT) {
    suspend_socket(monitored_socket);
    monitored_socket = INVALID_SOCK_FD;

    /* Don't process the message yet */
    return 1;
  }

  return 0;
}

/* ================================================== */

static struct Interface *
get_interface(int if_index)
{
  struct Interface *iface;
  unsigned int i;

  for (i = 0; i < ARR_GetSize(interfaces); i++) {
    iface = ARR_GetElement(interfaces, i);
    if (iface->if_index != if_index)
      continue;

    return iface;
  }

  return NULL;
}

/* ================================================== */

static void
process_hw_timestamp(struct Interface *iface, struct timespec *hw_ts,
                     NTP_Local_Timestamp *local_ts, int rx_ntp_length, int family,
                     int l2_length)
{
  struct timespec sample_phc_ts, sample_sys_ts, sample_local_ts, ts;
  double rx_correction, ts_delay, phc_err, local_err;

  if (HCL_NeedsNewSample(iface->clock, &local_ts->ts)) { //mefi84 VERMUTUNG: Dies dient zum Abschätzen des Offsets NIC/Systemtime
    if (!SYS_Linux_GetPHCSample(iface->phc_fd, iface->phc_nocrossts, iface->precision,
                                &iface->phc_mode, &sample_phc_ts, &sample_sys_ts,
                                &phc_err))
      return;

    LCL_CookTime(&sample_sys_ts, &sample_local_ts, &local_err);
    HCL_AccumulateSample(iface->clock, &sample_phc_ts, &sample_local_ts,
                         phc_err + local_err);

    update_interface_speed(iface); //mefi84 Warum wird das hier getan?
  }

  /* We need to transpose RX timestamps as hardware timestamps are normally
     preamble timestamps and RX timestamps in NTP are supposed to be trailer
     timestamps.  If we don't know the length of the packet at layer 2, we
     make an assumption that UDP data start at the same position as in the
     last transmitted packet which had a HW TX timestamp. */
  if (rx_ntp_length && iface->link_speed) {
    if (!l2_length)
      l2_length = (family == IPADDR_INET4 ? iface->l2_udp4_ntp_start :
                   iface->l2_udp6_ntp_start) + rx_ntp_length;

    /* Include the frame check sequence (FCS) */
    l2_length += 4;

    rx_correction = l2_length / (1.0e6 / 8 * iface->link_speed);

    UTI_AddDoubleToTimespec(hw_ts, rx_correction, hw_ts);
  }

  if (!HCL_CookTime(iface->clock, hw_ts, &ts, &local_err))
    return;

  if (!rx_ntp_length && iface->tx_comp)
    UTI_AddDoubleToTimespec(&ts, iface->tx_comp, &ts);
  else if (rx_ntp_length && iface->rx_comp)
    UTI_AddDoubleToTimespec(&ts, -iface->rx_comp, &ts);

  ts_delay = UTI_DiffTimespecsToDouble(&local_ts->ts, &ts);

  if (fabs(ts_delay) > MAX_TS_DELAY) {
    DEBUG_LOG("Unacceptable timestamp delay %.9f", ts_delay);
    return;
  }

  local_ts->ts = ts;
  local_ts->err = local_err;
  local_ts->source = NTP_TS_HARDWARE;
}

/* ================================================== */
/* Extract UDP data from a layer 2 message.  Supported is Ethernet
   with optional VLAN tags. */

static int
extract_udp_data(unsigned char *msg, NTP_Remote_Address *remote_addr, int len)
{
  unsigned char *msg_start = msg;

  remote_addr->ip_addr.family = IPADDR_UNSPEC;
  remote_addr->port = 0;

  /* Skip MACs */
  if (len < 12)
    return 0;
  len -= 12, msg += 12;

  /* Skip VLAN tag(s) if present */
  while (len >= 4 && msg[0] == 0x81 && msg[1] == 0x00)
    len -= 4, msg += 4;

  /* Skip IPv4 or IPv6 ethertype */
  if (len < 2 || !((msg[0] == 0x08 && msg[1] == 0x00) ||
                   (msg[0] == 0x86 && msg[1] == 0xdd)))
    return 0;
  len -= 2, msg += 2;

  /* Parse destination address and port from IPv4/IPv6 and UDP headers */
  if (len >= 20 && msg[0] >> 4 == 4) {
    int ihl = (msg[0] & 0xf) * 4;
    uint32_t addr;

    if (len < ihl + 8 || msg[9] != 17)
      return 0;

    memcpy(&addr, msg + 16, sizeof (addr));
    remote_addr->ip_addr.addr.in4 = ntohl(addr);
    remote_addr->port = ntohs(*(uint16_t *)(msg + ihl + 2));
    remote_addr->ip_addr.family = IPADDR_INET4;
    len -= ihl + 8, msg += ihl + 8;
#ifdef FEAT_IPV6
  } else if (len >= 48 && msg[0] >> 4 == 6) {
    int eh_len, next_header = msg[6];

    memcpy(&remote_addr->ip_addr.addr.in6, msg + 24, sizeof (remote_addr->ip_addr.addr.in6));
    len -= 40, msg += 40;

    /* Skip IPv6 extension headers if present */
    while (next_header != 17) {
      switch (next_header) {
        case 44:  /* Fragment Header */
          /* Process only the first fragment */
          if (ntohs(*(uint16_t *)(msg + 2)) >> 3 != 0)
            return 0;
          eh_len = 8;
          break;
        case 0:   /* Hop-by-Hop Options */
        case 43:  /* Routing Header */
        case 60:  /* Destination Options */
        case 135: /* Mobility Header */
          eh_len = 8 * (msg[1] + 1);
          break;
        case 51:  /* Authentication Header */
          eh_len = 4 * (msg[1] + 2);
          break;
        default:
          return 0;
      }

      if (eh_len < 8 || len < eh_len + 8)
        return 0;

      next_header = msg[0];
      len -= eh_len, msg += eh_len;
    }

    remote_addr->port = ntohs(*(uint16_t *)(msg + 2));
    remote_addr->ip_addr.family = IPADDR_INET6;
    len -= 8, msg += 8;
#endif
  } else {
    return 0;
  }

  /* Move the message to fix alignment of its fields */
  if (len > 0)
    memmove(msg_start, msg, len);

  return len;
}

/* ================================================== */

int
NIO_Linux_ProcessMessage(SCK_Message *message, NTP_Local_Address *local_addr,
                         NTP_Local_Timestamp *local_ts, int event)
{
  struct Interface *iface;
  int is_tx, ts_if_index, l2_length;

  is_tx = event == SCH_FILE_EXCEPTION;
  iface = NULL;

  ts_if_index = message->timestamp.if_index;
  if (ts_if_index == INVALID_IF_INDEX)
    ts_if_index = message->if_index;
  l2_length = message->timestamp.l2_length;

  if (!UTI_IsZeroTimespec(&message->timestamp.hw)) {
    iface = get_interface(ts_if_index);
    if (iface) {
      process_hw_timestamp(iface, &message->timestamp.hw, local_ts, !is_tx ? message->length : 0,
                           message->remote_addr.ip.ip_addr.family, l2_length);
    } else {
      DEBUG_LOG("HW clock not found for interface %d", ts_if_index);
    }

    /* If a HW transmit timestamp was received, resume processing
       of non-error messages on this socket */
    if (is_tx)
      resume_socket(local_addr->sock_fd);
  }

  if (local_ts->source == NTP_TS_DAEMON && !UTI_IsZeroTimespec(&message->timestamp.kernel) &&
      (!is_tx || UTI_IsZeroTimespec(&message->timestamp.hw))) {
    LCL_CookTime(&message->timestamp.kernel, &local_ts->ts, &local_ts->err);
    local_ts->source = NTP_TS_KERNEL;
  }

  /* If the kernel is slow with enabling RX timestamping, open a dummy
     socket to keep the kernel RX timestamping permanently enabled */
  if (!is_tx && local_ts->source == NTP_TS_DAEMON && ts_flags) {
    DEBUG_LOG("Missing kernel RX timestamp");
    if (dummy_rxts_socket == INVALID_SOCK_FD)
      dummy_rxts_socket = open_dummy_socket();
  }

  /* Return the message if it's not received from the error queue */
  if (!is_tx)
    return 0;
  //mefi84 Vermutlich wird hier das gesendete Paket ebenfalls extrahiert zusammen mit einem TS (falls man etwas gesendet hat, d.h. vermutlich nur im TX fall oder bei RX+Error?... analysiere woher RX TS kommen)
  /* The data from the error queue includes all layers up to UDP.  We have to
     extract the UDP data and also the destination address with port as there
     currently doesn't seem to be a better way to get them both. */
  l2_length = message->length;
  message->length = extract_udp_data(message->data, &message->remote_addr.ip, message->length);

  DEBUG_LOG("Extracted message for %s fd=%d len=%d",
            UTI_IPSockAddrToString(&message->remote_addr.ip),
            local_addr->sock_fd, message->length);

  /* Update assumed position of UDP data at layer 2 for next received packet */
  if (iface && message->length) {
    if (message->remote_addr.ip.ip_addr.family == IPADDR_INET4)
      iface->l2_udp4_ntp_start = l2_length - message->length;
    else if (message->remote_addr.ip.ip_addr.family == IPADDR_INET6)
      iface->l2_udp6_ntp_start = l2_length - message->length;
  }

  /* Drop the message if it has no timestamp or its processing failed */
  if (local_ts->source == NTP_TS_DAEMON) {
    DEBUG_LOG("Missing TX timestamp");
    return 1;
  }

  if (message->length < NTP_HEADER_LENGTH)
    return 1;

  NSR_ProcessTx(&message->remote_addr.ip, local_addr, local_ts, message->data, message->length);

  return 1;
}

/* ================================================== */

void
NIO_Linux_RequestTxTimestamp(SCK_Message *message, int sock_fd)
{
  if (!ts_flags)
    return;

  /* If a HW transmit timestamp is requested on a client socket, monitor
     events on the socket in order to avoid processing of a fast response
     without the HW timestamp of the request */
  if (ts_tx_flags & SOF_TIMESTAMPING_TX_HARDWARE && !NIO_IsServerSocket(sock_fd))
    monitored_socket = sock_fd; //mefi84 Annahme dass kein anderer Request dies überschreibt, da separiert

  /* Check if TX timestamping is disabled on this socket */
  if (permanent_ts_options || !NIO_IsServerSocket(sock_fd)) //mefi84 ????????? ein ClientSocket returnt hier immer...
    return;

  message->timestamp.tx_flags = ts_tx_flags; //mefi84 dieser Teil der Message wird sowieso nicht gesendet
}

/* ================================================== */

void
NIO_Linux_NotifySocketClosing(int sock_fd)
{
  resume_socket(sock_fd);
}
