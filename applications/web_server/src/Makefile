INCLUDE = $(ROOTFS_DIR)/usr/local/include/
LIB     = $(ROOTFS_DIR)/usr/local/lib

CFLAGS += -Wall -g -I$(INCLUDE) -L$(LIB) -lfcgi

BIN=web_handler
SRCS=main.o simplewebfactory.o fcgi.cpp simplewebfactory_url_html_map.o

%.o : %.cpp
	$(CXX) $< $(CFLAGS) -c -o $@

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))

$(BIN): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/sbin

all: $(BIN) install
