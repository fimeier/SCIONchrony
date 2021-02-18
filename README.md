


# Build-it
Define your SCIONDIR and run ./configure with the additional option --SCIONdir

./configure --SCIONdir=$SCIONDIR

Example:
```console
$./configure --SCIONdir=/home/fimeier/Dropbox/00ETH/HS20/MasterThesis/repos/scionproto --enable-godebug --enable-debug --enable-SCION
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
  --enable-godebug       Enables addition output for golang part (independent of --enable-debug)
  --enable-scionudpdualmode Enables SCION and UDP mode at the same time as client and server
[...]

```


# Disable built-in time syn service
sudo timedatectl set-ntp 0

# (Optional) Install Meinberg driver after kernel update
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