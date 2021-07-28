CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= 

TARGET   = client
INSTALL_DIR = /usr/local/
SOURCE   = ./client-tls-baremetal.c

ifeq ($(SSL),OPENSSL)
INCLUDE   = -I../../include -I.
LDFLAGS   = -lcrypto -lssl
CFLAGS    = -g -Wall $(INCLUDE) -DSSL_SUCCESS=1 -DSSL_FAILURE=0
else
INCLUDE   = -I../../include -I$(INSTALL_DIR)/include/wolfssl/ -I. -include options.h
LDFLAGS   = -lwolfssl
CFLAGS    = -g -Wall $(INCLUDE)
endif

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(LDFLAGS) $(SOURCE)

clean: FORCE
	-rm -f *.o $(TARGET)

FORCE:
	.PHONY: FORCE
