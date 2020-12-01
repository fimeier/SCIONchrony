##################################################
#
# chronyd/chronyc - Programs for keeping computer clocks accurate.
# 
# Copyright (C) Richard P. Curnow  1997-2003
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# =======================================================================
#
# Makefile template

SYSCONFDIR = /etc
BINDIR = /usr/scion//bin
SBINDIR = /usr/scion//sbin
LOCALSTATEDIR = /var
CHRONYVARDIR = /var/lib/chrony
DESTDIR =

CC = gcc
BACKUPCFLAGS = -O2 -g -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong --param=ssp-buffer-size=4 -Wmissing-prototypes -Wall -pthread
CFLAGS = -O0 -g -Wall -pthread

CPPFLAGS = 
LDFLAGS =  -pie -Wl,-z,relro,-z,now

EXTRA_OBJS = sys_generic.o sys_linux.o sys_timex.o sys_posix.o cmdmon.o manual.o pktlength.o ntp_auth.o ntp_core.o ntp_ext.o ntp_io.o ntp_sources.o addrfilt.o clientlog.o keys.o nameserv.o refclock.o refclock_phc.o refclock_pps.o refclock_shm.o refclock_sock.o nameserv_async.o hwclock.o ntp_io_linux.o rtc_linux.o hash_intmd5.o
EXTRA_OBJS_SCION = scion.o
OBJS = array.o cmdparse.o conf.o local.o logging.o main.o memory.o \
       reference.o regress.o rtc.o samplefilt.o sched.o socket.o sources.o sourcestats.o \
       stubs.o smooth.o sys.o sys_null.o tempcomp.o util.o $(EXTRA_OBJS) $(EXTRA_OBJS_SCION)

EXTRA_CLI_OBJS =  hash_intmd5.o

CLI_OBJS = array.o client.o cmdparse.o getdate.o memory.o nameserv.o \
           pktlength.o socket.o util.o $(EXTRA_CLI_OBJS) $(EXTRA_OBJS_SCION)

ALL_OBJS = $(OBJS) $(CLI_OBJS)

LIBS =  -lm 
EXTRA_LIBS = 
EXTRA_CLI_LIBS = 
EXTRA_LIBS_SCION = /home/fimeier/MasterThesis/repos/chrony/scion_api.so #SOLVE this: Full path needed when debuging with gdb.bash as root.. why?

# Until we have a main procedure we can link, just build object files
# to test compilation

all : go chronyd chronyc

go : 
	go build -buildmode=c-shared -o scion_api.so *.go

chronyd : $(OBJS)
	$(CC) $(CFLAGS) -o chronyd $(OBJS) $(LDFLAGS) $(LIBS) $(EXTRA_LIBS) $(EXTRA_LIBS_SCION)

chronyc : $(CLI_OBJS)
	$(CC) $(CFLAGS) -o chronyc $(CLI_OBJS) $(LDFLAGS) $(LIBS) $(EXTRA_CLI_LIBS) $(EXTRA_LIBS_SCION)

distclean : clean
	$(MAKE) -C doc distclean
	$(MAKE) -C test/unit distclean
	-rm -f .DS_Store
	-rm -f Makefile config.h config.log

clean :
	$(MAKE) -C test/unit clean
	-rm -f *.o *.s chronyc chronyd core.* *~
	-rm -f *.gcda *.gcno
	-rm -rf .deps
	-rm -rf *.dSYM

getdate.c : getdate.y
	bison -o getdate.c getdate.y

# This can be used to force regeneration of getdate.c
getdate :
	bison -o getdate.c getdate.y

# For install, don't use the install command, because its switches
# seem to vary between systems.

install: chronyd chronyc
	[ -d $(DESTDIR)$(SYSCONFDIR) ] || mkdir -p $(DESTDIR)$(SYSCONFDIR)
	[ -d $(DESTDIR)$(SBINDIR) ] || mkdir -p $(DESTDIR)$(SBINDIR)
	[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	[ -d $(DESTDIR)$(CHRONYVARDIR) ] || mkdir -p $(DESTDIR)$(CHRONYVARDIR)
	if [ -f $(DESTDIR)$(SBINDIR)/chronyd ]; then rm -f $(DESTDIR)$(SBINDIR)/chronyd ; fi
	if [ -f $(DESTDIR)$(BINDIR)/chronyc ]; then rm -f $(DESTDIR)$(BINDIR)/chronyc ; fi
	cp chronyd $(DESTDIR)$(SBINDIR)/chronyd
	chmod 755 $(DESTDIR)$(SBINDIR)/chronyd
	cp chronyc $(DESTDIR)$(BINDIR)/chronyc
	chmod 755 $(DESTDIR)$(BINDIR)/chronyc
	$(MAKE) -C doc install

docs :
	$(MAKE) -C doc docs

install-docs :
	$(MAKE) -C doc install-docs

%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

%.s : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -S $<

quickcheck : chronyd chronyc
	$(MAKE) -C test/unit check
	cd test/simulation && ./run
	cd test/system && ./run

check : chronyd chronyc
	$(MAKE) -C test/unit check
	cd test/simulation && ./run -i 20 -m 2
	cd test/system && ./run

print-chronyd-objects :
	@echo $(OBJS)

Makefile : Makefile.in configure
	@echo
	@echo Makefile needs to be regenerated, run ./configure
	@echo
	@exit 1

.deps:
	@mkdir .deps

.deps/%.d: %.c | .deps
	@$(CC) -MM $(CPPFLAGS) -MT '$(<:%.c=%.o) $@' $< -o $@

ifndef NODEPS
-include $(ALL_OBJS:%.o=.deps/%.d)
endif
