CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
CTARGET_CP   = Client-tls-ext-cipher-
STARGET   = Server-tls-
INSTALL_DIR = /usr/local/
CSOURCE_CP  = ./client-tls-ext-cipher.c
SSOURCE   = ../client-server/server-tls.c
COBJ_CP   = $(CSOURCE_CP:.c=.o)
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

all: $(STARGET)$(SSL) $(CTARGET_CP)$(SSL)

$(STARGET)$(SSL): $(SOBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CTARGET_CP)$(SSL): $(COBJ_CP)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean: FORCE
	-rm -f ../client-server/*.o *.o
	-rm -f ../client-server/$(STARGET)* $(CTARGET_CP)*

FORCE:
.PHONY: FORCE
