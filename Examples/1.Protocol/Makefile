CC = gcc
#CC = clang
SRCROOT = .
SRCDIRS := $(shell find $(SRCROOT) -type d -not -path ".")

openssl:
	@for d in $(SRCDIRS); do $(MAKE) -C $$d CC=$(CC) SSL=OPENSSL; done

wolfssl:
	@for d in $(SRCDIRS); do $(MAKE) -C $$d CC=$(CC); done

clean:
	@for d in $(SRCDIRS); do $(MAKE) -C $$d clean; done

