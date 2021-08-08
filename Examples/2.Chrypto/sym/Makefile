CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
TARGET   = aescbc

COMM_SOURCE = ../common/cipher_main.c

INSTALL_DIR = /usr/local/
SOURCE   = ./aes-cbc.c


ifeq ($(SSL),OPENSSL)
INCLUDE   = -I../../include
LDFLAGS   = -lcrypto -lssl
CFLAGS    = -g -Wall $(INCLUDE) -DSSL_SUCCESS=1 -DSSL_FAILURE=0
else
INCLUDE   = -I../../include -I$(INSTALL_DIR)/include/wolfssl/ -include options.h
LDFLAGS   = -lwolfssl
CFLAGS    = -g -Wall $(INCLUDE)
endif

all: $(TARGET)

$(TARGET): $(SOURCE) $(COMM_SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(LDFLAGS) $(COMM_SOURCE) $(SOURCE)

clean: FORCE
	-rm -f *.o $(TARGET)

FORCE:
.PHONY: FORCE
