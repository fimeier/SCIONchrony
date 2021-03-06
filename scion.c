#include "scion.h"
#ifndef _SCION_API_H
#define _SCION_API_H
#include "scion/go/scion_api.h"
#endif

static fdInfo *fdInfos[1024];

static int checkNTPfile;
static int checkNTPexcept;

#define MAXNUMMAPPINGS 100
static addressMapping *ntpServers[MAXNUMMAPPINGS];
static int nummappings = 0;

static int ntpPort = NTP_PORT;
static int commandPort = DEFAULT_CANDM_PORT;

void SCIONsetNtpPorts(int _ntpPort, int _cmdPort)
{
    ntpPort = _ntpPort;
    commandPort = _cmdPort;
}

char *getNTPServerSCIONAddress(char *address)
{ //TODO fix this ugly datastructure
    for (int i = 0; i < nummappings; i++)
    {
        addressMapping *server = ntpServers[i];
        if (server == NULL)
        {
            return NULL;
        }

        if (strcmp(address, server->addressIP) == 0)
        {
            return server->addressSCION;
        }
    }
    return NULL;
}

void SCION_parse_source(char *line, char *type)
{
    DEBUG_LOG("\t------> type = %s", type);
    DEBUG_LOG("\t------> line = %s", line);

    /* Parse options */
    int n = 0;
    int ok;
    char *cmd;

    for (; *line; line += n)
    {
        cmd = line;
        line = CPS_SplitWord(line);
        //DEBUG_LOG("\t------> line3 = %s", line);
        //DEBUG_LOG("\t------> cmd = %s", cmd);

        if (!strcasecmp(cmd, "server")) //example: server 85.195.227.162:123 1-ff00:0:110,10.80.45.83:11111
        {
            DEBUG_LOG("\t------> This is an IP <-> SCION mapping");
            char d[] = " ";

            //IP address
            char *addressIP = strtok(line, d);
            DEBUG_LOG("\t------> addressIP = %s", addressIP);

            //SCION address
            char *addressSCION = strtok(NULL, d);
            DEBUG_LOG("\t------> addressSCION = %s", addressSCION);

            ok = 0;
            for (int i = 0; i < MAXNUMMAPPINGS; i++)
            {
                addressMapping *server = ntpServers[i];
                if (server == NULL)
                {
                    addressMapping *server = calloc(1, sizeof(addressMapping));
                    strcpy(server->addressIP, addressIP);
                    strcpy(server->addressSCION, addressSCION);
                    ntpServers[i] = server;
                    DEBUG_LOG("\t------> Mapping added to Configuration");
                    ok = 1;

                    assert(nummappings == i);
                    nummappings = i + 1;

                    break;
                }
            }
            if (ok != 1)
            {
                DEBUG_LOG("\t------> There was a problem adding the Mapping to the Configuration");
            }
            n = 0;
        }
        else if (!strcasecmp(cmd, "sciondAddr")) //example: sciondAddr 127.0.0.1:30255
        {
            DEBUG_LOG("\t------> This is the ScionD Address");
            char d[] = " ";

            //IP sciondAddr
            char *addressIP = strtok(line, d);
            DEBUG_LOG("\t------> sciondAddr = %s", addressIP);

            ok = SetSciondAddr(addressIP);
            if (ok != 1)
            {
                DEBUG_LOG("\t------> There was a problem adding the Mapping to the Configuration");
            }
            n = 0;
        }
        else if (!strcasecmp(cmd, "localAddr")) //example: localAddr 1-ff00:0:112,10.80.45.83
        {
            DEBUG_LOG("\t------> This is the local SCION Address");
            char d[] = " ";

            //IP sciondAddr
            char *addressIP = strtok(line, d);
            DEBUG_LOG("\t------> localAddr = %s", addressIP);

            ok = SetLocalAddr(addressIP);
            if (ok != 1)
            {
                DEBUG_LOG("\t------> There was a problem adding the Mapping to the Configuration");
            }
            n = 0;
        }
    }
}

void SCION_Initialise(void)
{
    //start the receive logic for the ntp server: at this moment all socket options should be set
    SCIONstartntp();
}

int ts_flags_p52 = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OPT_PKTINFO | SOF_TIMESTAMPING_OPT_TX_SWHW | SOF_TIMESTAMPING_OPT_CMSG;
int ts_tx_flags_p52 = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE;

/*
                                    *****************Explanation of the used flags**********************

TIMESTAMPS as "activated" by NIO_Linux_Initialise(), NIO_Linux_SetTimestampSocketOptions()

activated on my system for 0.0.0.0.123 (NTP), all RX flags, but no TX flags (normal NTP Server mode)
int ts_flags_p52 = 25692 = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OPT_PKTINFO | SOF_TIMESTAMPING_OPT_TX_SWHW | SOF_TIMESTAMPING_OPT_CMSG;
setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE, 1, sizeof(val));
setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &ts_flags_p52, sizeof(val));

int ts_tx_flags_p52 = 3 = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE



ATTENTION:      i)      NTP Server has in normal mode just RX activated
                ii)     SOF_TIMESTAMPING_OPT_TX_SWHW is always set as part of ts_flags (assuming program logic)
                iii)    As a Client RX|TX is activated
                iv)     some of the settings are also (have to be) activated during NIO_Linux_Initialise()::add_interface() 
                v)      SIEHE UGLY HACK: Beim senden wird explizit TS f??r einzelnes Paket angefordert

RX:
    SOF_TIMESTAMPING_SOFTWARE       <=> REPORT any software timestamps when available.
    SOF_TIMESTAMPING_RX_SOFTWARE    <=> Request rx timestamps when data enters the kernel.
    SOF_TIMESTAMPING_RAW_HARDWARE   <=> REPORT hardware timestamps as generated by SOF_TIMESTAMPING_TX_HARDWARE when available
    SOF_TIMESTAMPING_RX_HARDWARE    <=> Request rx timestamps generated by the network adapter
    SOF_TIMESTAMPING_OPT_PKTINFO    <=> Enable the SCM_TIMESTAMPING_PKTINFO control message for incoming packets with hardware timestamps. The message contains struct scm_ts_pktinfo
    SOF_TIMESTAMPING_OPT_CMSG       <=> Support recv() cmsg for all timestamped packets. Control messages are already supported unconditionally on all packets with receive timestamps and on IPv6 packets with transmit timestamp. This option extends them to IPv4 packets with transmit timestamp. One use case is to correlate packets with their egress device, by enabling socket option IP_PKTINFO simultaneously.

TX:
    SOF_TIMESTAMPING_TX_SOFTWARE    <=> Request tx timestamps when data leaves the kernel.
    SOF_TIMESTAMPING_TX_HARDWARE    <=> Request tx timestamps generated by the network adapter. This flag can be enabled via both socket options and control messages.
    SOF_TIMESTAMPING_OPT_TX_SWHW    <=> Request both hardware and software timestamps for outgoing packets when SOF_TIMESTAMPING_TX_HARDWARE and SOF_TIMESTAMPING_TX_SOFTWARE are enabled at the same time.


* SO_TIMESTAMPING
  Generates timestamps on reception, transmission or both. Supports
  multiple timestamp sources, including hardware. Supports generating
  timestamps for stream sockets.

1.3 SO_TIMESTAMPING (also SO_TIMESTAMPING_OLD and SO_TIMESTAMPING_NEW):

Supports multiple types of timestamp requests. As a result, this
socket option takes a bitmap of flags, not a boolean. In

  err = setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &val, sizeof(val));

val is an integer with any of the following bits set. Setting other
bit returns EINVAL and does not change the current state.

The socket option configures timestamp generation for individual
sk_buffs (1.3.1), timestamp reporting to the socket's error
queue (1.3.2) and options (1.3.3). Timestamp generation can also
be enabled for individual sendmsg calls using cmsg (1.3.4). <= z.B. f??r interleaved Mode n??tig!

*/

/* A wrapper around close() to support Scion */
int SCION_close(int sock_fd)
{
    DEBUG_LOG("Closing socket %d", sock_fd);

    if (fdInfos[sock_fd] != NULL)
    {
        if (fdInfos[sock_fd]->socketType == 0)
        {
            SCIONgoclose(sock_fd);
        }
        else
        {
            DEBUG_LOG("----> There is no socket in scion. Reason = %d => not calling SCIONgoclose()", fdInfos[sock_fd]->socketType);
        }
        free(fdInfos[sock_fd]);
    }
    return close(sock_fd);
}

/* A wrapper around socket() to support Scion */
int SCION_socket(int __domain, int __type, int __protocol)
{
    DEBUG_LOG("Creating socket with domain=%d type=%d protocol=%d", __domain, __type, __protocol);

    //We always open a (normal) socket AND sometimes also a "Scion-Socket"
    int fd = socket(__domain, __type, __protocol);

    int doNotCreateScionSocket = 0; //0==create a Scion Socket ;-)

    //Collecting some informations, also for future changes
    //Some of them aren't used anymore. Work in progress
    fdInfo *sinfo = calloc(1, sizeof(fdInfo));
    fdInfos[fd] = sinfo;
    sinfo->fd = fd;
    sinfo->domain = __domain;
    sinfo->type = __type;
    sinfo->protocol = __protocol;
    sinfo->connectionType = NOT_CONNECTED;
    //sinfo->if_index = IFINDEX; //not used anymore

    //mostly debuggin, BUT also used for decision making (at the moment identification of socket typ)
    //=> there can be more usecases in the future
    //Hint: At the moment of this call it isn't always possible to decide if we need a "Scion Socket"
    //=> sometimes we create one and remove it afterwards once we know more (during bind(), connect(),...)
    switch (__domain)
    {
    case AF_INET:
        DEBUG_LOG("----> domain = AF_INET");
        break;
    case AF_UNIX:
        DEBUG_LOG("----> domain = AF_UNIX");
        doNotCreateScionSocket = 1;
        sinfo->socketType = SOMETHING_ELSE;
        break;
    default:
        DEBUG_LOG("----> domain = tbd");
        doNotCreateScionSocket = 1;
        sinfo->socketType = SOMETHING_ELSE;
        break;
    }

    switch (__type)
    {
    case SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK:
        DEBUG_LOG("----> type = SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK");
        break;
    case SOCK_DGRAM | SOCK_NONBLOCK:
        DEBUG_LOG("----> type = SOCK_DGRAM | SOCK_NONBLOCK");
        break;
    case SOCK_DGRAM | SOCK_CLOEXEC:
        DEBUG_LOG("----> type = SOCK_DGRAM | SOCK_CLOEXEC");
        break;
    case SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK:
        DEBUG_LOG("----> type = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK (a socket for NTS or other TCP)");
        doNotCreateScionSocket = 1;
        sinfo->socketType = IS_CHRONY_STREAM_SOCKET;
        break;
    default:
        DEBUG_LOG("----> type = tbd");
        break;
    }

    DEBUG_LOG("----> fd = %d (received from system, using this for SCION)", fd);

    if (!doNotCreateScionSocket)
    {
        int SCION_fd = SCIONgosocket(__domain, __type, __protocol, sinfo);
        if (fd != SCION_fd)
        {
            LOG_FATAL("fd != SCION_fd i.e. %d != %d", fd, SCION_fd);
        }
    }
    else
    {
        DEBUG_LOG("----> fd = %d Not creating a SCION socket as this is (probably for nts or other things)", fd);
    }

    return fd;
}

/* A wrapper around setsockopt() to support Scion */
int SCION_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen)
{
    DEBUG_LOG("\tSetting options fd=%d level=%d optname=%d", __fd, __level, __optname);

    /*
    Motivation for this design:
    ->There can be multiple calls to setsockopt with a variety of (level X optname X optval) arguments
    SCION_setsockopt() will store them for future usecase in a "matrix": fdi->level_optname_value[scion_level][scion_optname] = *((int *)__optval);
    We decide what we are interessted in (compare the enums SCION_LEVEL, SCION_OPTNAME,...) to get a somehow compact representation
    Goal: Store everything the caller gave us, if we are interessted in the information
    */

    int scion_level = SCION_LE_UNDEFINED;
    int scion_optname = SCION_OPT_UNDEFINED;

    switch (__level)
    {
        /************************************************************/

    case IPPROTO_IP:
        DEBUG_LOG("\t|----> level = IPPROTO_IP");
        scion_level = SCION_IPPROTO_IP;
        switch (__optname)
        {
        case IP_PKTINFO:
            DEBUG_LOG("\t|----> optname = IP_PKTINFO");
            scion_optname = SCION_IP_PKTINFO;
            break;
        case IP_FREEBIND:
            DEBUG_LOG("\t|----> optname = IP_FREEBIND");
            scion_optname = SCION_IP_FREEBIND;
            break;
        default:
            DEBUG_LOG("\t|----> optname = %d", __optname);
            scion_optname = SCION_OPT_UNDEFINED;
            break;
        }
        break;

        /************************************************************/

    case SOL_SOCKET:
        DEBUG_LOG("\t|----> level = SOL_SOCKET");
        scion_level = SCION_SOL_SOCKET;
        switch (__optname)
        {
        case SO_REUSEADDR:
            DEBUG_LOG("\t|----> optname = SO_REUSEADDR");
            scion_optname = SCION_SO_REUSEADDR;
            break;
        case SO_REUSEPORT:
            DEBUG_LOG("\t|----> optname = SO_REUSEPORT");
            scion_optname = SCION_SO_REUSEPORT;
            break;
        case SO_TIMESTAMPING:
            DEBUG_LOG("\t|----> optname = SO_TIMESTAMPING");
            scion_optname = SCION_SO_TIMESTAMPING;
            break;
        case SO_BROADCAST:
            DEBUG_LOG("\t|----> optname = SO_BROADCAST");
            scion_optname = SCION_SO_BROADCAST;
            break;
        case SO_SELECT_ERR_QUEUE:
            DEBUG_LOG("\t|----> optname = SO_SELECT_ERR_QUEUE");
            scion_optname = SCION_SO_SELECT_ERR_QUEUE;
            break;
        default:
            DEBUG_LOG("\t|----> optname = %d", __optname);
            scion_optname = SCION_OPT_UNDEFINED;
            break;
        }
        break;
        /************************************************************/

    default:
        DEBUG_LOG("\t|----> level = %d", __level);
        DEBUG_LOG("\t|----> optname = %d", __optname);
        scion_optname = SCION_OPT_UNDEFINED;
        break;
    }

    int createTxTimestamp = 0;
    int createRxTimestamp = 0;
    int createHwTimestamp = 0;
    int optval = *((int *)__optval);
    if (*((int *)__optval) != 0)
    {
        DEBUG_LOG("\t|----> optval = %d => activate option", *((int *)__optval));
        /*
        Assumption: SO_TIMESTAMPING is only called once to set all options
        => if this isn't the case more complicated logic is needed to prevent possible bugs
        Hint: Chrony is testing for settings at the beginning. But once Chrony really wants to create a socket, 
        all flags for the same optname are set at once, therefore the following approach is okay
        */
        if (__optname == SO_TIMESTAMPING)
        {
            if (*((int *)__optval) == ts_flags_p52)
            { //access ts_flags in ntp_io_linux
                DEBUG_LOG("\t|---->  This is the option to activate RX-Timestamps (HW/Kernel)");
                createTxTimestamp = 0;
                createRxTimestamp = 1;
            }
            if (*((int *)__optval) == (ts_flags_p52 | ts_tx_flags_p52))
            { //access ts_flags in ntp_io_linux
                DEBUG_LOG("\t|----> This is the option to activate TX/RX-Timestamps (HW/Kernel)");
                createTxTimestamp = 1;
                createRxTimestamp = 1;
            }

            /* New logic: overrides stuff above */
            //Hint: We always activate Rx, probably Tx and if requested HW (for both)
            //Hint2: In theory we should also parse how chrony (or another application) is expecting the timestamps (structs etc...).. but this is overkill. Anyway: The infos are stored

            // not using: SOF_TIMESTAMPING_RAW_HARDWARE, SOF_TIMESTAMPING_OPT_PKTINFO, SOF_TIMESTAMPING_OPT_TX_SWHW, SOF_TIMESTAMPING_OPT_CMSG
            int rxEnable = optval & (SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE);
            if (rxEnable)
            {
                createRxTimestamp = 1;
            }
            else
            { //not true while Chrony is testing for supported socket options
                //DEBUG_LOG("\t|----> Warning!!! There is probably a bug in the logic, as we do not enable Rx Timestamps!!!!");
            }

            //Enable HW Timestamps?
            int hwEnable = optval & (SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_TX_HARDWARE);
            /*int a = optval & SOF_TIMESTAMPING_TX_HARDWARE;
            int b = optval & SOF_TIMESTAMPING_RAW_HARDWARE;
            int c = optval & SOF_TIMESTAMPING_RX_HARDWARE;*/
            if (hwEnable)
            {
                createHwTimestamp = 1;
            }

            //enable TX Timestamps?
            int txEnable = optval & (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE);
            /*int e = optval & SOF_TIMESTAMPING_TX_SOFTWARE;
            int f = optval & SOF_TIMESTAMPING_TX_HARDWARE;*/
            if (txEnable)
            {
                createTxTimestamp = 1;
            }
        }
    }
    else
    {
        DEBUG_LOG("\t|----> optval = 0 => disable option (NOT IMPLEMENTED)");
    }

    DEBUG_LOG("\t|----> Info: We always set the socket options in the c-world");
    int result = setsockopt(__fd, __level, __optname, __optval, __optlen);

    if (fdInfos[__fd] != NULL && fdInfos[__fd]->socketType == 0) //if this is not a scion "socket", we return
    {
        //at the moment we are only interessted in SO_TIMESTAMPING options
        //we can call SCIONgosetsockopt() also for other settings (not needed at the moment)
        if (__optname == SO_TIMESTAMPING)
        {
            fdInfo *fdi = fdInfos[__fd];

            fdi->level_optname_value[scion_level][scion_optname] = *((int *)__optval);
            fdi->createTxTimestamp = createTxTimestamp;
            fdi->createRxTimestamp = createRxTimestamp;
            fdi->createHwTimestamp = createHwTimestamp;
            if (SCIONgosetsockopt(__fd) < 0)
            {
                DEBUG_LOG("\t|----> SCIONgosetsockopt() returned an error!");
            }
        }
    }

    //Returning this for chrony
    return result;
}

/*
    TODO? How can I define (__CONST_SOCKADDR_ARG __addr) in the header and use it afterwards as I do it?

    ---> no problem in the debugger. Function defined as...
                SCION_bind(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
        ...then "viewing" the datastructure as "(struct sockaddr*)__addr"
    ---> Why does the compiler prevents me from compiling similar code?
*/
int SCION_bind(int __fd, struct sockaddr *__addr, socklen_t __len)
{
    DEBUG_LOG("\tBinding fd=%d", __fd);

    int r = 0;

    assert(ntpPort != commandPort);

    if (fdInfos[__fd] != NULL) //should always be true
    {
        fdInfo *fdi = fdInfos[__fd];
        SCK_SockaddrToIPSockAddr(__addr, __len, &fdi->boundTo);
        DEBUG_LOG("\t|----> %s", UTI_IPSockAddrToString(&fdi->boundTo));

        if (fdi->boundTo.port == ntpPort)
        {
            DEBUG_LOG("\t|----> calling SCIONgobind() as this is is Chrony's NTP-Server Socket");
            fdi->connectionType = IS_NTP_SERVER;
            int callRegister = 0; //we don't want to start it, as we do not know the correct TS-settings
            r = SCIONgobind(__fd, fdi->boundTo.port, callRegister);
            DEBUG_LOG("\t|----> SCIONgobind() return-state: %d", r);

            r += bind(__fd, __addr, __len); //assumptions: <0 is an error
            DEBUG_LOG("\t|----> SCIONgobind() Also bound normal port. Combined return state: %d", r);
            return r;
        }
        else if (fdi->boundTo.port == commandPort)
        {
            DEBUG_LOG("\t|----> NOT calling SCIONgobind() as this is is Chrony's Command Socket.");
            DEBUG_LOG("\t|----> Will delete datastructures in go-World and call standard bind()");
            fdi->connectionType = IS_CMD_SOCKET;
            fdi->socketType = IS_CMD_SOCKET;
            SCIONgoclose(__fd);
            return bind(__fd, __addr, __len);
        }
    }
    else
    {
        DEBUG_LOG("nonexisting fdInfo: cannot add informations");
    }

    //Todo: Decide if this is still needed
    return bind(__fd, __addr, __len);
}

int SCION_getsockopt(int __fd, int __level, int __optname, void *__restrict __optval, socklen_t *__restrict __optlen)
{
    DEBUG_LOG("Getting options fd=%d level=%d optname=%d", __fd, __level, __optname);
    return getsockopt(__fd, __level, __optname, __optval, __optlen);
}

/*
TODO CONNECTED_TO_NTP_SERVER einzige M??glichkeit? Falls ja kann unten NTP_UDP gesetzt werden
*/
int SCION_connect(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len, IPSockAddr *addr)
{
    //TODO ist this safe?? Buffer??? CHANGE THIS!!!! Should be okay...
    char *remoteAddress = UTI_IPSockAddrToString(addr);

    DEBUG_LOG("Connecting socket fd=%d to %s", __fd, remoteAddress);

    if (fdInfos[__fd] != NULL) //should always be true
    {
        fdInfo *fdi = fdInfos[__fd];

        if (fdi->socketType == 0)
        {
            char *ntpServerAsScionAddress = getNTPServerSCIONAddress(remoteAddress);

            //Use Scion if we have a mapping, otherwise there is no point in doing this
            if (ntpServerAsScionAddress != NULL) //strcmp(remoteAddress, ntpServer1) == 0)
            {
                DEBUG_LOG("\t|----->  is an ntp server");

                fdi->connectionType = CONNECTED_TO_NTP_SERVER;
                strcpy(fdi->remoteAddress, remoteAddress);
                strcpy(fdi->remoteAddressSCION, ntpServerAsScionAddress);

                int callRegister = 0; //we don't want to start it, as we do not know the correct TS-settings
                return SCIONgoconnect(__fd, callRegister);
            }
            //If we don't have a SCION address this implies we are connecting to a common NTP-Server
            else
            {
                DEBUG_LOG("\t|----->  We don't have a scion address. Will delete datastructures in go-Wold and call standard connect()");
                fdi->socketType = fdi->connectionType = SOMETHING_ELSE; //HAHA: connectionType kann garnicht gesetzt sein
                SCIONgoclose(__fd);
                return connect(__fd, __addr, __len);
            }
        }
        else
        {
            DEBUG_LOG("----> There is no socket in scion. Reason = %d. Will use standard connect()", fdi->socketType);
            return connect(__fd, __addr, __len); //probably not needed
        }
    }
    else
    {
        LOG_FATAL("Corrupted datastructure: fdInfos[%d] doesn't exist", __fd);
    }
    return connect(__fd, __addr, __len); //for the compiler
}

ssize_t SCION_sendmsg(int __fd, const struct msghdr *__message, int __flags)
{
    int status = -1;
    DEBUG_LOG("Sending message on socket fd=%d", __fd);

    int txTsOptions = 0;
    if (DEBUG)
    {
        struct mmsghdr msgvec;
        msgvec.msg_hdr = *__message;
        msgvec.msg_len = 0;
        printMMSGHDR(&msgvec, 1, SCION_IP_TX_NTP_MSG);
    }

    txTsOptions = getRequestedTxFlags(__message);

    if ((fdInfos[__fd] != NULL) && fdInfos[__fd]->socketType == 0)
    {

        int status;
        /* Chronyd talks as a Client to a Server */
        if (fdInfos[__fd]->connectionType == CONNECTED_TO_NTP_SERVER) //impliziert prim??r dass connected und IP bekannt
        {
            DEBUG_LOG("\t|----> using SCION");
            DEBUG_LOG("\t|----> connected to %s i.e. %s\n", fdInfos[__fd]->remoteAddress, fdInfos[__fd]->remoteAddressSCION);
            status = SCIONgosendmsg(__fd, __message, __flags, NULL, 0);
            DEBUG_LOG("\t|----> Sent message on socket fd=%d with status=%d(<-#bytes sent)", __fd, status);
            if (status < 0)
            {
                errno = SCIONERROR;
            }
            return status;
        }

        if (__message->msg_namelen != 0)
        {
            switch (((struct sockaddr *)__message->msg_name)->sa_family)
            {
            case AF_INET:
            {

                //TODO fix this ugly construct: depends on how the GO-Part registers the clients
                char remoteAddress[MAXADDRESSLENGTH] = ""; //initialization is needed!!!
                strcat(remoteAddress, inet_ntoa(((struct sockaddr_in *)__message->msg_name)->sin_addr));
                // TODO: Add port
                strcat(remoteAddress, ":");
                char portAsStr[10];
                sprintf(portAsStr, "%u", ntohs(((struct sockaddr_in *)__message->msg_name)->sin_port));
                strcat(remoteAddress, portAsStr);

                int clientType = IsScionNode(remoteAddress);

                /* Scion-Chronyd talks as a Server to a Scion Client */
                if (0 < clientType)
                {

                    DEBUG_LOG("\t|----> sending to %s", remoteAddress);

                    if (fdInfos[__fd] != NULL && fdInfos[__fd]->connectionType == IS_NTP_SERVER)
                    {
                        DEBUG_LOG("\t|----> sending Message over Scion. We are the Chrony-Scion NTP Server");
                        if (txTsOptions == (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE))
                        {
                            DEBUG_LOG("\t|----> sending Message over Scion. We are the Chrony-Scion NTP Server. For this Packet we request TX Kernel and HW Timestamps!!!");
                        }
                        if (txTsOptions == (SOF_TIMESTAMPING_TX_SOFTWARE))
                        {
                            DEBUG_LOG("\t|----> sending Message over Scion. We are the Chrony-Scion NTP Server. For this Packet we request TX Kernel Timestamps!!!");
                        }
                        status = SCIONgosendmsg(__fd, __message, __flags, remoteAddress, txTsOptions);
                        if (status < 0)
                        {
                            errno = SCIONERROR;
                        }
                        return status;
                    }
                }

                /* Scion-Chronyd talks as a Server to a UDP Client */
                if (clientType < 0)
                {
                    DEBUG_LOG("\t|----> not a connection to a scion target. Not using SCION, even tough we are the SCION SERVER");
                    status = sendmsg(__fd, __message, __flags);
                    DEBUG_LOG("\t|----> Sent message on socket fd=%d with status=%d(<-#bytes sent)", __fd, status);
                    return status;
                }

                if (clientType == 0)
                {
                    DEBUG_LOG("\t|----> a connection to a scion target, but outdated. We are the SCION SERVER");
                    DEBUG_LOG("\t|----> Behaviour on socket fd=%d sending to %s needs to be defined", __fd, remoteAddress);
                    return -1;
                }
                break;
            }
            case AF_UNIX:
                LOG_FATAL("\t|----> sending to = %s (AF_UNIX NOT IMPLEMENTED)", ((struct sockaddr_un *)__message->msg_name)->sun_path);
                break;
            default:
                LOG_FATAL("\t|----> sending to (NOT IMPLEMENTED!!!) = tbd");
                break;
            }
        }
    }

    DEBUG_LOG("\t|----> not a connection to a scion target. Not using SCION!");
    status = sendmsg(__fd, __message, __flags);
    DEBUG_LOG("\t|----> Sent message on socket fd=%d with status=%d(<-#bytes sent)", __fd, status);

    return status;
}

//a silent copy of printMMSGHDR
int getRequestedTxFlags(const struct msghdr *_msg_hdr)
{
    struct msghdr *msg_hdr;
    msg_hdr = (struct msghdr *)_msg_hdr;

    int txTsOptions = 0;

    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg_hdr); cmsg; cmsg = CMSG_NXTHDR(msg_hdr, cmsg))
    {

        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING)
        {
            int *ts_tx_flags;
            ts_tx_flags = (void *)CMSG_DATA(cmsg);
            txTsOptions = *ts_tx_flags;
        }
    }

    return txTsOptions;
}

//TODO How to prevent redeclaration? Is defined in (chrony's) socket.c
union sockaddr_all
{
    struct sockaddr_in in4;
#ifdef FEAT_IPV6
    struct sockaddr_in6 in6;
#endif
    struct sockaddr_un un;
    struct sockaddr sa;
};

// This functions is a pretty printer and very useful to understand what is going on
int printMMSGHDR(struct mmsghdr *msgvec, int n, int SCION_TYPE)
{
    int uglyHack = 0; //this is not safe!!!!
    // int dataEncapLayer2 = (SCION_TYPE == SCION_IP_TX_ERR_MSG) || (SCION_TYPE == SCION_IP_RX_NTP_MSG) ? 1 : 0; //0=SCION_IP_TX_NTP_MSG directly in NTP_Packet struct
    int dataEncapLayer2 = (SCION_TYPE == SCION_IP_TX_ERR_MSG) ? 1 : 0; //0=SCION_IP_TX_NTP_MSG directly in NTP_Packet struct
    int sendNTP = SCION_TYPE == SCION_IP_TX_NTP_MSG ? 1 : 0;
    int receiveNTP = SCION_TYPE == SCION_IP_RX_NTP_MSG ? 1 : 0;
    if (SCION_TYPE == SCION_IP_TX_ERR_MSG)
    {
        DEBUG_LOG("Called with SCION_TYPE=%d (getting Transmit-TS as error message) => ntp data pointed to by *iov_base is assumed to be in a %s", SCION_TYPE, dataEncapLayer2 ? "layer 2 packet" : "NTP_Packet struct");
    }
    if (SCION_TYPE == SCION_IP_TX_NTP_MSG)
    {
        DEBUG_LOG("Called with SCION_TYPE=%d (sending NTP packet) => ntp data pointed to by *iov_base is assumed to be in a %s", SCION_TYPE, dataEncapLayer2 ? "layer 2 packet" : "NTP_Packet struct");
    }
    if (SCION_TYPE == SCION_IP_RX_NTP_MSG)
    {
        DEBUG_LOG("Called with SCION_TYPE=%d (receiving NTP packet incl. TS's) => ntp data pointed to by *iov_base is assumed to be in a %s", SCION_TYPE, dataEncapLayer2 ? "layer 2 packet" : "NTP_Packet struct");
    }
    for (int i = 0; i < n; i++)
    {
        struct msghdr *msg_hdr = &msgvec[i].msg_hdr;

        DEBUG_LOG("\t|-----> Printing message %d: %s", i + 1, (msg_hdr->msg_flags == MSG_ERRQUEUE) ? "This is (probably) a local error i.e. arrival of TS's" : "");
        if (!sendNTP)
            DEBUG_LOG("\t\t\tmsg_len=%u", msgvec[i].msg_len);
        DEBUG_LOG("\t\t\tmsg_hdr @ %p", msg_hdr);

        if (msg_hdr->msg_namelen == 0)
        {
            DEBUG_LOG("\t\t\t\tmsg_hdr.msg_namelen=%d", msg_hdr->msg_namelen);
            DEBUG_LOG("\t\t\t\tmsg_hdr.msg_name=%s", "NULL");
        }
        else
        {
            DEBUG_LOG("\t\t\t\tmsg_hdr.msg_namelen=%d", msg_hdr->msg_namelen);
            if (msg_hdr->msg_namelen <= sizeof(union sockaddr_all) &&
                msg_hdr->msg_namelen > sizeof(((struct sockaddr *)msg_hdr->msg_name)->sa_family)) //????
            {
                switch (((struct sockaddr *)msg_hdr->msg_name)->sa_family)
                {
                case AF_INET:
                    DEBUG_LOG("\t\t\t\tmsg_hdr.msg_name (AF_INET) = %s:%u", inet_ntoa(((struct sockaddr_in *)msg_hdr->msg_name)->sin_addr), ntohs(((struct sockaddr_in *)msg_hdr->msg_name)->sin_port));
                    break;
                case AF_UNIX:
                    DEBUG_LOG("\t\t\t\tmsg_hdr.msg_name (AF_UNIX) = %s", ((struct sockaddr_un *)msg_hdr->msg_name)->sun_path);
                    break;
                default:
                    DEBUG_LOG("\t\t\t\tmsg_hdr.msg_name (NOT IMPLEMENTED!!!) = tbd");
                    break;
                }
            }
        }

        DEBUG_LOG("\t\t\t\tmsg_hdr.msg_iovlen=%lu", msg_hdr->msg_iovlen);

        for (int io = 0; io < msg_hdr->msg_iovlen; io++) //probably always 1 vector
        {
            DEBUG_LOG("\t\t\t\t|-----> Printing vector=%d:", io);
            DEBUG_LOG("\t\t\t\t\t*iov_base=%p", msg_hdr->msg_iov[io].iov_base);
            DEBUG_LOG("\t\t\t\t\tiov_len=%lu %s", msg_hdr->msg_iov[io].iov_len, dataEncapLayer2 ? "(HINWEIS: Gibt die Gr??sse des Buffers an. Dieser Wert wird durch den caller nicht abgepasst)" : "");
        }

        /*       
       The field msg_control, which has length msg_controllen, points to a
       buffer for other protocol control-related messages or miscellaneous
       ancillary data.  When recvmsg() is called, msg_controllen should con???
       tain the length of the available buffer in msg_control; upon return
       from a successful call it will contain the length of the control mes???
       sage sequence.

       The messages are of the form:

           struct cmsghdr {
               size_t cmsg_len;    // Data byte count, including header (type is socklen_t in POSIX)
               int    cmsg_level;  // Originating protocol 
               int    cmsg_type;   // Protocol-specific type
                                    // followed by
               unsigned char cmsg_data[];
           };

       Ancillary data should be accessed only by the macros defined in
       cmsg(3).
       */
        DEBUG_LOG("\t\t\t\tmsg_hdr->msg_control@%p", msg_hdr->msg_control);
        DEBUG_LOG("\t\t\t\tmsg_hdr->msg_controllen=%lu", msg_hdr->msg_controllen);

        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(msg_hdr); cmsg; cmsg = CMSG_NXTHDR(msg_hdr, cmsg))
        {
            int processed = 0;
            DEBUG_LOG("\t\t\t\tProcessing *cmsghdr@%p\tcmsg->cmsg_len=%lu\tcmsg->cmsg_level=%d\tcmsg->cmsg_type=%d", cmsg, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);
#ifdef HAVE_IN_PKTINFO
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
            {
                processed = 1;
                DEBUG_LOG("\t\t\t\t|-----> *cmsghdr@%p is of type IP_PKTINFO", cmsg);

                struct in_pktinfo ipi;

                memcpy(&ipi, CMSG_DATA(cmsg), sizeof(ipi));
                DEBUG_LOG("\t\t\t\t\tipi.ipi_ifindex=%d (Interface index) TODO<-Variable machen beim erstellen!!!!!", ipi.ipi_ifindex);
                DEBUG_LOG("\t\t\t\t\tipi.ipi_spec_dst.s_addr=%s (Local address.. wrong->? Routing destination address)", inet_ntoa(ipi.ipi_spec_dst));
                DEBUG_LOG("\t\t\t\t\tipi.ipi_addr.s_addr=%s (Header destination address)", inet_ntoa(ipi.ipi_addr));
            }

#endif

#ifdef HAVE_LINUX_TIMESTAMPING
#ifdef HAVE_LINUX_TIMESTAMPING_OPT_PKTINFO
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING_PKTINFO)
            {
                processed = 1;
                DEBUG_LOG("\t\t\t\t|-----> *cmsghdr@%p is of type SCM_TIMESTAMPING_PKTINFO", cmsg);

                struct scm_ts_pktinfo ts_pktinfo;

                memcpy(&ts_pktinfo, CMSG_DATA(cmsg), sizeof(ts_pktinfo));
                DEBUG_LOG("\t\t\t\t\tts_pktinfo.if_index=%u", ts_pktinfo.if_index);
                DEBUG_LOG("\t\t\t\t\tts_pktinfo.pkt_length=%u (l2_length?)", ts_pktinfo.pkt_length);
            }
#endif

            if (!sendNTP) //HINT SCM_TIMESTAMPING==SO_TIMESTAMPING... could also distinguish by len
            {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING) ///CMSG_LEN(sizeof(__u32))
                {
                    processed = 1;
                    DEBUG_LOG("\t\t\t\t|-----> *cmsghdr@%p is of type SCM_TIMESTAMPING", cmsg);

                    struct scm_timestamping ts3;

                    memcpy(&ts3, CMSG_DATA(cmsg), sizeof(ts3));
                    struct timespec kernel = ts3.ts[0];
                    struct timespec hw = ts3.ts[2];
                    if (kernel.tv_sec)
                    {
                        DEBUG_LOG("\t\t\t\t\tKerne-TS tv_sec=%ld tv_nsec=%ld", kernel.tv_sec, kernel.tv_nsec);
                    }
                    if (hw.tv_sec)
                    {
                        DEBUG_LOG("\t\t\t\t\tHW-TS tv_sec=%ld tv_nsec=%ld", hw.tv_sec, hw.tv_nsec);
                    }
                }
            }
            else
            {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING)
                {
                    processed = 1;
                    DEBUG_LOG("\t\t\t\t|-----> *cmsghdr@%p is of type SO_TIMESTAMPING (!!!This requests TX-Timestamps for this packet!!!", cmsg);

                    int *ts_tx_flags;
                    ts_tx_flags = (void *)CMSG_DATA(cmsg);
                    DEBUG_LOG("\t\t\t\t\tts_tx_flags=%d (should be 3, i.e. SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE", *ts_tx_flags);

                    uglyHack = *ts_tx_flags;

                    if (uglyHack != (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE))
                    {
                        DEBUG_LOG("\t\t\t\t\tts_tx_flags=%d probably SOF_TIMESTAMPING_TX_SOFTWARE..???", *ts_tx_flags);
                    }
                }
            }

            if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR)
            {
                processed = 1;
                DEBUG_LOG("\t\t\t\t|-----> *cmsghdr@%p is of type IP_RECVERR", cmsg);
                struct sock_extended_err *sock_err;
                sock_err = (struct sock_extended_err *)CMSG_DATA(cmsg);
                DEBUG_LOG("\t\t\t\t|-----> sock_err->ee_errno=%u %s", sock_err->ee_errno, sock_err->ee_errno == ENOMSG ? "(ENOMSG)" : "");
                DEBUG_LOG("\t\t\t\t|-----> sock_err->ee_origin=%d %s", sock_err->ee_origin, sock_err->ee_origin == SO_EE_ORIGIN_TIMESTAMPING ? "(SO_EE_ORIGIN_TIMESTAMPING)" : "");
                DEBUG_LOG("\t\t\t\t|-----> sock_err->ee_type=%d", sock_err->ee_type);
                DEBUG_LOG("\t\t\t\t|-----> sock_err->ee_code=%d", sock_err->ee_code);
                DEBUG_LOG("\t\t\t\t|-----> sock_err->ee_pad=%d", sock_err->ee_pad);
                DEBUG_LOG("\t\t\t\t|-----> sock_err->ee_info=%d %s", sock_err->ee_data, sock_err->ee_info == SCM_TSTAMP_SND ? "(SCM_TSTAMP_SND)" : "");
                DEBUG_LOG("\t\t\t\t|-----> sock_err->ee_data=%d", sock_err->ee_data);
                if (sock_err->ee_errno == ENOMSG && sock_err->ee_info == SCM_TSTAMP_SND && sock_err->ee_origin == SO_EE_ORIGIN_TIMESTAMPING)
                {
                    DEBUG_LOG("\t\t\t\t|-----> everything as excpected. Can be ignored");
                }
            }
#endif

            if (!processed)
            {
                DEBUG_LOG("\t\t\t\t|-----> *cmsghdr@%p is of type UNKNOWN", cmsg);
            }
        }

        DEBUG_LOG("\t\t\t\tmsg_hdr->msg_flags=%d", msg_hdr->msg_flags);

        /*
    l2_length = message->length;
    message->length = extract_udp_data(message->data, &message->remote_addr.ip, message->length);
    //mefi84 *msg==*iov_base  *remote_addr==(to fill in the address)  len==(msg_len in mmsghdr struct)

    */

        for (int io = 0; io < msg_hdr->msg_iovlen; io++) //probably always 1 vector
        {
            if (sendNTP || receiveNTP)
            {
                DEBUG_LOG("\t\t\textracting ntp data from iov_base=%p:", msg_hdr->msg_iov[io].iov_base);
                printNTPPacket(msg_hdr->msg_iov[io].iov_base, msg_hdr->msg_iov[io].iov_len);
            }
            else
            {
                DEBUG_LOG("\t\t\textracting ntp data from iov_base=%p:", msg_hdr->msg_iov[io].iov_base);
                void *baseSource = msg_hdr->msg_iov[io].iov_base;
                int len = msgvec[i].msg_len; //length of the received msg (has nothing to do with iov_base buffer length)
                void *debugBuffer = calloc(1, MAXMESSAGESIZE);
                NTP_Remote_Address *remote_addr = calloc(1, sizeof(NTP_Remote_Address));
                memcpy(debugBuffer, baseSource, len); //create copy, do not change data
                                                      //
                //mefi84 *msg==*iov_base  *remote_addr==(to fill in the address)  len==(msg_len in mmsghdr struct)

                len = SCION_extract_udp_data(debugBuffer, remote_addr, len);
                printNTPPacket(debugBuffer, len);

                free(debugBuffer); //correct?
                free(remote_addr);
            }
        }
    }

    return uglyHack;
}

void printNTPPacket(void *ntpPacket, int len)
{
    //

    NTP_Packet *ntp = ntpPacket;

    if (len < NTP_HEADER_LENGTH || len % 4U != 0)
    {
        DEBUG_LOG("NTP packet has invalid length %d", len);
        return;
    }

    /*
 //Macros to work with the lvm field
#define NTP_LVM_TO_LEAP(lvm) (((lvm) >> 6) & 0x3)
#define NTP_LVM_TO_VERSION(lvm) (((lvm) >> 3) & 0x7)
#define NTP_LVM_TO_MODE(lvm) ((lvm) & 0x7)
#define NTP_LVM(leap, version, mode) \
  ((((leap) << 6) & 0xc0) | (((version) << 3) & 0x38) | ((mode) & 0x07))
*/

    DEBUG_LOG("\t\t\t|-----> lvm=%u lvm=0o%o (chrony shows octal) lvm=0x%x", ntp->lvm, ntp->lvm, ntp->lvm); //siehe macros chrony: NTP_LVM_TO_VERSION(packet->lvm) NTP_LVM_TO_MODE(packet->lvm);
    DEBUG_LOG("\t\t\t|-----> stratum=%u", ntp->stratum);
    DEBUG_LOG("\t\t\t|-----> poll=%d", ntp->poll);
    DEBUG_LOG("\t\t\t|-----> precision=%d", ntp->precision);

    DEBUG_LOG("\t\t\t|-----> root_delay=%u", ntp->root_delay);
    DEBUG_LOG("\t\t\t|-----> root_dispersion=%u", ntp->root_dispersion);
    DEBUG_LOG("\t\t\t|-----> reference_id=%u", ntp->reference_id);

    DEBUG_LOG("\t\t\t|-----> reference_ts=%u.%u", ntp->reference_ts.hi, ntp->reference_ts.lo);
    DEBUG_LOG("\t\t\t|-----> originate_ts=%u.%u", ntp->originate_ts.hi, ntp->originate_ts.lo);
    DEBUG_LOG("\t\t\t|-----> receive_ts=%u.%u", ntp->receive_ts.hi, ntp->receive_ts.lo);
    DEBUG_LOG("\t\t\t|-----> transmit_ts=%u.%u", ntp->transmit_ts.hi, ntp->transmit_ts.lo);

    DEBUG_LOG("\t\t\t|-----> extensions=tbd %s", len > NTP_HEADER_LENGTH ? "there are extensions as the packet is longer than expected" : "");

    /*
    uint8_t lvm; //mefi84 LeapIndicator(2)||VersionNumber(3)||Mode(3) == 8 Bits
    uint8_t stratum;
    int8_t poll;
    int8_t precision;

    NTP_int32 root_delay;
    NTP_int32 root_dispersion;
    NTP_int32 reference_id;

    NTP_int64 reference_ts;
    NTP_int64 originate_ts;
    NTP_int64 receive_ts;
    NTP_int64 transmit_ts;

    uint8_t extensions[NTP_MAX_EXTENSIONS_LENGTH];
    */
}

int SCION_recvmmsg(int __fd, struct mmsghdr *__vmessages, unsigned int __vlen, int __flags, struct timespec *__tmo)
{
    /* I do not set msg_flags... chrony is okay with it. CHECK IT FOR INTERLEAVED MODE
MSG_EOR == 128
End of record was received (if supported by the protocol).
MSG_OOB == 1
Out-of-band data was received.
MSG_TRUNC == 32
Normal data was truncated.
MSG_CTRUNC == 8

MSG_ERRQUEUE	= 0x2000  == 8192 f??r alles was von error queue gelesen wird

Was Chrony beim empfang pr??ft
  if (msg->msg_flags & MSG_TRUNC) {
    log_message(sock_fd, 1, message, "Truncated", NULL);
    r = 0;
  }

  if (msg->msg_flags & MSG_CTRUNC) {
    log_message(sock_fd, 1, message, "Truncated cmsg in", NULL);
    r = 0;
  }

    */

    /*Receive up to VLEN messages as described by VMESSAGES from socket FD.
   Returns the number of messages received or -1 for errors.*/
    int n = 0;

    //assuming this are the only possible flags
    int receiveFlag = (__flags & MSG_ERRQUEUE) ? SCION_MSG_ERRQUEUE : SCION_FILE_INPUT;
    int scion_type = (__flags & MSG_ERRQUEUE) ? SCION_IP_TX_ERR_MSG : SCION_IP_RX_NTP_MSG;

    //printMMSGHDR(__vmessages, __vlen, scion_type);

    char *flagsMeaning;
    flagsMeaning = (receiveFlag == SCION_MSG_ERRQUEUE) ? "MSG_ERRQUEUE" : "file input";
    DEBUG_LOG("Receiving message on socket fd=%d with flags=%d => %s", __fd, __flags, flagsMeaning);

    if ((fdInfos[__fd] != NULL) && fdInfos[__fd]->socketType == 0) // >0 means there is no "socket" in scion
    {

        //Chronyd acts as a Client
        if (fdInfos[__fd]->connectionType == CONNECTED_TO_NTP_SERVER)
        {

            n = SCIONgorecvmmsg(__fd, __vmessages, __vlen, __flags, __tmo);
            DEBUG_LOG("|----->received %d messages over SCION connection", n);
        }
        //Chronyd acts as the NTP Server
        else if (fdInfos[__fd] != NULL && fdInfos[__fd]->connectionType == IS_NTP_SERVER)
        {
            n = SCIONgorecvmmsg(__fd, __vmessages, __vlen, __flags, __tmo);
            DEBUG_LOG("|----->received %d messages over SCION connection (we are the NTP Server)", n);

            //TODO We should also check it if it isn't 0 (no starvation for udp clients)
            //But in the end, we should use the infos from the last select call to decide what we want to call...
            //Easy to implement alternative: Call it with zero wait time. ADJUST vmessages and vlen before calling it

            if ((checkNTPfile && !(__flags & MSG_ERRQUEUE)) || (checkNTPexcept && (__flags & MSG_ERRQUEUE)))
            {
                DEBUG_LOG("|----->we should call recvmmsg() to get at most %d-messages checkNTPfile=%d checkNTPexcept=%d", __vlen - n, checkNTPfile, checkNTPexcept);
                DEBUG_LOG("|----->received %d messages over SCION connection... now trying UDP-channel... checkNTPfile=%d checkNTPexcept=%d", n, checkNTPfile, checkNTPexcept);
                int nc = recvmmsg(__fd, &__vmessages[n], __vlen - n, __flags, __tmo);
                if (nc >= 0 || n == 0) //ignore it if we received msg's over scion, but return -1 if we haven't received something over scion
                {
                    n += nc;
                }
                DEBUG_LOG("|----->received %d messages over NON-scion connection", n);
            }
            /*
            if (n == 0)
            {
                //We also serve the normal UDP socket for incoming clients
                DEBUG_LOG("|----->received %d messages over SCION connection... now trying UDP-channel... checkNTPfile=%d checkNTPexcept=%d", n, checkNTPfile, checkNTPexcept);
                n = recvmmsg(__fd, __vmessages, __vlen, __flags, __tmo);
                DEBUG_LOG("|----->received %d messages over NON-scion connection", n);
            }
            */
        }
    }
    else
    {
        n = recvmmsg(__fd, __vmessages, __vlen, __flags, __tmo);
        DEBUG_LOG("|----->received %d messages over NON-scion connection", n);
    }

    printMMSGHDR(__vmessages, n, scion_type);

    return n;
}

/*Returns the number of ready descriptors, or -1 for errors.
nfds   This argument should be set to the highest-numbered file
        descriptor in any of the three sets, plus 1.  The
        indicated file descriptors in each set are checked, up to this limit
              */

int SCION_select(int __nfds, fd_set *__restrict __readfds,
                 fd_set *__restrict __writefds,
                 fd_set *__restrict __exceptfds,
                 struct timeval *__restrict __timeout)
{

    DEBUG_LOG("SCION_select(...) called....");
    checkNTPfile = checkNTPexcept = 0;
    int n = SCIONselect(__nfds, __readfds, __writefds, __exceptfds, __timeout, &checkNTPfile, &checkNTPexcept);
    /*
     DEBUG_LOG("SCION_select(...) ACHTUNG DAS IST C-SELECT!!!");
    DEBUG_LOG("SCION_select(...) ACHTUNG DAS IST C-SELECT!!!");
    DEBUG_LOG("SCION_select(...) ACHTUNG DAS IST C-SELECT!!!");
    DEBUG_LOG("SCION_select(...) ACHTUNG DAS IST C-SELECT!!!");
    int n = select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
*/
    DEBUG_LOG("SCION_select(...) found %d ready fd's and checkNTPfile=%d checkNTPexcept=%d", n, checkNTPfile, checkNTPexcept);

    //Debug stuff
    int readyFDs = n;
    for (int fd = 0; readyFDs && fd < __nfds; fd++)
    { //mefi84 man geht alle FD's durch...
        if (__exceptfds && FD_ISSET(fd, __exceptfds))
        {
            DEBUG_LOG("SCION_select(...) fd=%d reported an exception", fd);
            readyFDs--;
        }

        if (__readfds && FD_ISSET(fd, __readfds))
        {
            DEBUG_LOG("SCION_select(...) fd=%d reported file input", fd);
            readyFDs--;
        }

        if (__writefds && FD_ISSET(fd, __writefds))
        {
            DEBUG_LOG("SCION_select(...) fd=%d reported file output", fd);
            readyFDs--;
        }
    }

    return n;
}

//linekr problem... use directly chronys definition on ntp_io_linux.c

/* ================================================== */
/* Extract UDP data from a layer 2 message.  Supported is Ethernet
   with optional VLAN tags. */
//mefi84 *msg==*iov_base  *remote_addr==(to fill in the address)  len==(msg_len in mmsghdr struct)
int SCION_extract_udp_data(unsigned char *msg, NTP_Remote_Address *remote_addr, int len)
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
    if (len >= 20 && msg[0] >> 4 == 4)
    {
        int ihl = (msg[0] & 0xf) * 4;
        uint32_t addr;

        if (len < ihl + 8 || msg[9] != 17)
            return 0;

        memcpy(&addr, msg + 16, sizeof(addr));
        remote_addr->ip_addr.addr.in4 = ntohl(addr);
        remote_addr->port = ntohs(*(uint16_t *)(msg + ihl + 2));
        remote_addr->ip_addr.family = IPADDR_INET4;
        len -= ihl + 8, msg += ihl + 8;
#ifdef FEAT_IPV6
    }
    else if (len >= 48 && msg[0] >> 4 == 6)
    {
        int eh_len, next_header = msg[6];

        memcpy(&remote_addr->ip_addr.addr.in6, msg + 24, sizeof(remote_addr->ip_addr.addr.in6));
        len -= 40, msg += 40;

        /* Skip IPv6 extension headers if present */
        while (next_header != 17)
        {
            switch (next_header)
            {
            case 44: /* Fragment Header */
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
            case 51: /* Authentication Header */
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
    }
    else
    {
        return 0;
    }

    /* Move the message to fix alignment of its fields */
    if (len > 0)
        memmove(msg_start, msg, len);

    return len;
}
