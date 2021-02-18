# Build-it
Define your SCIONDIR and run ./configure with the additional option --SCIONdir

./configure --SCIONdir=$SCIONDIR


./configure --SCIONdir=/home/fimeier/Dropbox/00ETH/HS20/MasterThesis/repos/scionproto --enable-godebug --enable-debug

HINT: Use ./configure --help


# Disable built-in time syn service
sudo timedatectl set-ntp 0

# Meinbergkarten Install jeweils nach Kernel Updates nötig

sudo apt-get install linux-headers-generic

mbgtools download: Link= und entpacken

cd ~/Downloads/mbgtools-lx-4.2.14/
 * make clean
 * make
 * sudo make install

Nach der Installation kann das Kernelmodul erstmalig geladen werden.
 * sudo modprobe mbgclock

Commands
 * sudo mbgsvcd -f //this starts the SHM driver
 * refclock SHM 0 poll 3 refid GNS1 //the needed configuration in chrony to use the ref clock 