# Meinbergkarten Install jeweils nach Kernel Updates nötig

sudo apt-get install linux-headers-generic

mbgtools download: Link= und entpacken

cd ~/Downloads/mbgtools-lx-4.2.14/
 * make clean
 * make
 * make install

Nach der Installation kann das Kernelmodul erstmalig geladen werden.
 * sudo modprobe mbgclock

Commands
 * sudo mbgsvcd -f