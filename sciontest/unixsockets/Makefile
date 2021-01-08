CC = gcc
BACKUPCFLAGSORIGINAL = -O2 -g -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong --param=ssp-buffer-size=4 -Wmissing-prototypes -Wall -pthread
BACKUPCFLAGMEINS = -O0 -g -Wall -pthread
CFLAGS = -O0 -g -Wall -pthread

OBJS1 = siteOne.o
OBJS2 = siteTwo.o

all : s1 s2

s1 : $(OBJS1)
	$(CC) $(CFLAGS) -o 1siteOne $(OBJS1)

s2 : $(OBJS2)
	$(CC) $(CFLAGS) -o 2siteTwo $(OBJS2)
