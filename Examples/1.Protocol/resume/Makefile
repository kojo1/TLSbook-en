CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
CTARGET_R = Client-resume-tls-
CTARGET_S = Client-session-tls-
STARGET   = Server-resume-tls-
INSTALL_DIR = /usr/local/
CSOURCE_R = ./client-tls-resume.c
CSOURCE_S = ./client-tls-session.c
SSOURCE   = ./server-tls-resume.c
COBJ_R    = $(CSOURCE_R:.c=.o)
COBJ_S    = $(CSOURCE_S:.c=.o)
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

all: $(STARGET)$(SSL) $(CTARGET_R)$(SSL)  $(CTARGET_S)$(SSL)

$(STARGET)$(SSL): $(SOBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CTARGET_R)$(SSL): $(COBJ_R)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CTARGET_S)$(SSL): $(COBJ_S)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean: FORCE
	-rm -f *.o
	-rm -f session.bin
	-rm -f $(STARGET)* $(CTARGET_R)* $(CTARGET_S)*

FORCE:
.PHONY: FORCE
