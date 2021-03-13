#CC = gcc
CC = clang
SSL = OPENSSL
#SSL = WOLFSSL
DEBUG= no
CTARGET   = PSK-client-
STARGET   = PSK-server-

ifeq ($(SSL),OPENSSL)
INCLUDE   = -I../../include
LDFLAGS   = -lcrypto -lssl
else
INCLUDE   = -I../../include -I/usr/local/include/wolfssl/ -include options.h
LDFLAGS   = -lwolfssl
endif

CFLAGS    = -g -Wall

CSOURCE	  = ./psk-client.c
SSOURCE   = ./psk-server.c
COBJ      = $(CSOURCE:.c=.o)
SOBJ      = $(SSOURCE:.c=.o)
OBJS      = $(COBJ) $(SOBJ)

.c.o:
	@$(CC) $(CFLAGS) $(INCLUDE) -o $@ -c $<

all: clean $(OBJS)
	@$(CC) $(CFLAGS) -o $(CTARGET)$(SSL) $(COBJ) $(LDFLAGS)
	@$(CC) $(CFLAGS) -o $(STARGET)$(SSL) $(SOBJ) $(LDFLAGS)

clean: FORCE
	-rm -f *.o
	-rm -f $(STARGET)$(SSL) $(CTARGET)$(SSL)

FORCE:
.PHONY: FORCE
