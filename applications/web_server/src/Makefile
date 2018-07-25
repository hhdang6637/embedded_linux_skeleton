CFLAGS += -g -lfcgi -lapp

BIN=web_handler
SRCS=main.o simplewebfactory.o fcgi.cpp simplewebfactory_url_html_map.o simplewebfactory_url_js_map.o system_manager_js.o \
Exception.o Field.o Parser.o firmware.o

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
