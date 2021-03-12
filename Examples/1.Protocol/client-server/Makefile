CC = gcc
#CC = clang
SSL = OPENSSL
#SSL = WOLFSSL
DEBUG= no
CTARGET   = TLS-client-
STARGET   = TLS-server-

ifeq ($(SSL),OPENSSL)
CFLAGS    = -g -Wall
LDFLAGS   = -lcrypto -lssl
else
CFLAGS    = -g -Wall -DUSE_WOLFSSL
INCLUDE   = -I/usr/local/include/wolfssl/ -include options.h
LDFLAGS   = -lwolfssl
endif

CSOURCE	  = ./tls-client.c
SSOURCE   = ./tls-server.c

all: clean client server

server: $(SSOURCE)
	$(CC) $(CFLAGS) $(INCLUDE) -o $(STARGET)$(SSL) $(SSOURCE) $(LDFLAGS)

client: $(CSOURCE)
	$(CC) $(CFLAGS) $(INCLUDE) -o $(CTARGET)$(SSL) $(CSOURCE) $(LDFLAGS)

clean: FORCE
	-rm -f *.o
	-rm -f $(STARGET)$(SSL) $(CTARGET)$(SSL)

FORCE:
.PHONY: FORCE
