INCLUDE = $(ROOTFS_DIR)/usr/local/include/
LIB     = $(ROOTFS_DIR)/usr/local/lib

CFLAGS += -Wall -g -I$(INCLUDE) -L$(LIB) -lfcgi

BIN=hello_world
SRCS=main.o

%.o : %.c
	$(CC) $< $(CFLAGS) -c -o $@

OBJS   = $(patsubst %.c,%.o,$(SRCS))

$(BIN): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/bin

all: $(BIN) install
