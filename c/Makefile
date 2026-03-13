CC      ?= gcc
AR      ?= ar
CFLAGS  ?= -Wall -Wextra -std=c99 -O2 -pedantic
CFLAGS  += -I. -fstack-protector-strong -D_FORTIFY_SOURCE=2

SRCS = checksum/checksum.c \
       packet_parser/packet_parser.c \
       raw_socket/raw_socket.c \
       arp/arp.c

OBJS = $(SRCS:.c=.o)
LIB  = libnetstack.a

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB)

.PHONY: all clean
