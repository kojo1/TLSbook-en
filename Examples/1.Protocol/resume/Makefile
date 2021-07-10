CC = gcc
#CC = clang
SSL = OPENSSL
#SSL = WOLFSSL
DEBUG= no
CTARGET   = Client-resume-tls-
STARGET   = Server-resume-tls-
INSTALL_DIR = /usr/local/
CSOURCE   = ./client-tls-resume.c
SSOURCE   = ./server-tls-resume.c
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
	-rm -f session.bin
	-rm -f $(STARGET)* $(CTARGET)*

FORCE:
.PHONY: FORCE
