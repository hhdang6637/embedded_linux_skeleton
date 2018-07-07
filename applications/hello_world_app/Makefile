# CC       = gcc
CFLAGS += -Wall -g

BIN=hello_world
SRCS=main.o

%.o : %.c
	$(CC) $(CFLAGS) $< -c -o $@

OBJS   = $(patsubst %.c,%.o,$(SRCS))

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/bin

all: $(BIN) install
