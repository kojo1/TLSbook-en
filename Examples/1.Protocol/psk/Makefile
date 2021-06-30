CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
CTARGET   = Client-tls-psk-
STARGET   = Server-tls-psk-
INSTALL_DIR = /usr/local/
CSOURCE	  = ./client-tls-psk.c
SSOURCE   = ./server-tls-psk.c
COBJ      = $(CSOURCE:.c=.o)
SOBJ      = $(SSOURCE:.c=.o)

ifeq ($(SSL),OPENSSL)
INCLUDE   = -I../../include
LDFLAGS   = -lcrypto -lssl
CFLAGS    = -g -Wall $(INCLUDE) -DSSL_SUCCESS=1 -DSSL_FAILURE=0
else
INCLUDE   = -I../../include -I$(INSTALL_DIR)/include/wolfssl/ -include options.h
LDFLAGS   = -lwolfssl
CFLAGS    = -g -Wall $(INCLUDE)
endif

all: $(STARGET)$(SSL) $(CTARGET)$(SSL)

$(STARGET)$(SSL): $(SOBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CTARGET)$(SSL): $(COBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean: FORCE
	-rm -f *.o
	-rm -f $(STARGET)$(SSL) $(CTARGET)$(SSL)

FORCE:
.PHONY: FORCE
