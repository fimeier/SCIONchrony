[![Go Report Card](https://goreportcard.com/badge/github.com/sciontime/chrony)](https://goreportcard.com/report/github.com/sciontime/chrony)

## SCIONchrony / this fork

Join [SCIONLab](https://www.scionlab.org) if you're interested in playing with
SCION in an operational global test deployment of SCION.

This fork of [chrony/chrony](https://git.tuxfamily.org/chrony/chrony.git) alows chrony the use SCION as an underlay network.

# Building
1. Download this repository

2. Configure the project: ./configure --SCIONdir=$SCIONDIR

3. make

Important: (As of 1.3.2021) Use the fork Scion Time available at [sciontime/scion](https://github.com/sciontime/scion).

Example output configure:
```console
$./configure --SCIONdir=/home/ethz/repos/scionproto --enable-godebug --enable-debug --enable-SCION
[...]
Features : +SCION +CMDMON +NTP +REFCLOCK +RTC +PRIVDROP -SCFILTER -SIGND +ASYNCDNS +NTS -READLINE +SECHASH +IPV6 +DEBUG +GODEBUG +SCIONUDPDUALMODE
Creating Makefile
Creating doc/Makefile
Creating test/unit/Makefile
Creating go.mod
go: creating new go.mod: module github.com/sciontime/chrony
```

HINT: Use ./configure --help
```console
$ ./configure --help
[...]
SCION setting
  --SCIONdir=DIR         location of github.com/scionproto/scion (go.mod)
  --enable-SCION         Enable SCION support (is always enabled at the moment, as we do not change the files, only the Makefile)
  --enable-godebug       Enables additional output for golang part (independent of --enable-debug)
  --enable-scionudpdualmode Enables SCION and UDP mode at the same time as client and server
[...]

```

# Some Hints
Consult the official documentation [offical documentation](https://chrony.tuxfamily.org/) for other installation options and configurations. SCIONchrony provides the same options/functionalities as the official version, plus some more SCION related features.

## Configuration
SCIONchrony has some additional directives for chrony's configuration file ([chrony.conf(5) Manual Page](https://chrony.tuxfamily.org/doc/4.0/chrony.conf.html))

SCION sciondAddr \<IPv4>:\<Port>

SCION localAddr \<ISD-AS>,\<IPv4>

SCION server \<IPv4>:\<Port> \<ISD-AS>,\<IPv4>:\<Port>

Example:
```console
SCION sciondAddr 127.0.0.1:30255
SCION localAddr 1-ff00:0:112,10.80.45.120

#there must be a matching "server" directive for each "SCION server"
server 10.80.45.241 port 123 xleave iburst
SCION server 10.80.45.241:123 1-ff00:0:112,10.80.45.241:123

```

## Disable built-in time syn service
sudo timedatectl set-ntp 0

## (Optional) Install Meinberg driver after kernel update
```console
#Install pre-requirements. Consult README in mbgtools for details.
sudo apt-get install linux-headers-generic

#download and unpack mbgtools
wget https://www.meinbergglobal.com/download/drivers/mbgtools-lx-4.2.14.tar.gz

#mbgtools build/install
cd mbgtools-lx-4.2.14/
make clean
make
sudo make install

#load the kernelmodule after installation
sudo modprobe mbgclock
```
Useful Commands
```console
#Start the SHM driver, and provide infos about system clock. Chrony can use this reference clock with the following config: refclock SHM 0 poll 3 refid GNS1
sudo mbgsvcd -f 

#details about used GNSS
mbgstatus
```