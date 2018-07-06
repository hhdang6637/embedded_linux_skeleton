# CC       = gcc
# CFLAGS +=

BIN=system_manager_daemon
SRCS=main.o system_manager.o

%.o : %.c
	$(CC) $(CFLAGS) $< -c -o $@

OBJS   = $(patsubst %.c,%.o,$(SRCS))

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/sbin

all: $(BIN) install
