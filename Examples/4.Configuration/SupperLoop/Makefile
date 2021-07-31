CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= 

INSTALL_DIR = /usr/local/

CLIENT   = client
SERVER   = server
CLIENT_SOURCE   = ./client-tls-sp.c
SERVER_SOURCE   = ./server-tls-sp.c

ifeq ($(SSL),OPENSSL)
INCLUDE   = -I../../include -I.
LDFLAGS   = -lcrypto -lssl
CFLAGS    = -g -Wall $(INCLUDE) -DSSL_SUCCESS=1 -DSSL_FAILURE=0
else
INCLUDE   = -I../../include -I$(INSTALL_DIR)/include/wolfssl/ -I. -include options.h
LDFLAGS   = -lwolfssl
CFLAGS    = -g -Wall $(INCLUDE)
endif

all: $(CLEINT) $(SERVER)

$(CLIENT): $(CLIENT_SOURCE)
	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT_SOURCE) $(LDFLAGS)

$(SERVER): $(SERVER_SOURCE)
	$(CC) $(CFLAGS) -o $(SERVER) $(SERVER_SOURCE) $(LDFLAGS)

clean: FORCE
	-rm -f *.o $(TARGET)

FORCE:
	.PHONY: FORCE
