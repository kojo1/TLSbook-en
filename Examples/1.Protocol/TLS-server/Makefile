CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
ifeq ($(SSL),OPENSSL)
TARGET    = TLS-server-openssl
CFLAGS    = -g -Wall
LDFLAGS   = -lcrypto -lssl
else
TARGET    = TLS-server-wolfssl
CFLAGS    = -g -Wall -DUSE_WOLFSSL
LDFLAGS   = -lwolfssl
endif

LIBS      =
INCLUDE   =
SRCDIR    = ./
ifeq "$(strip $(SRCDIR))" ""
  SRCDIR  = ./src
endif
SOURCES   = $(wildcard $(SRCDIR)/*.c)
OBJDIR    = ./
ifeq "$(strip $(OBJDIR))" ""
  OBJDIR  = .
endif
OBJECTS   = $(addprefix $(OBJDIR)/, $(notdir $(SOURCES:.c=.o)))
DEPENDS   = $(OBJECTS:.o=.d)

$(TARGET): $(OBJECTS) $(LIBS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ -c $<

all: clean $(TARGET)

clean: FORCE
	-rm -f *.o
	-rm -f $(OBJECTS) $(DEPENDS) $(TARGET)

FORCE:
	
