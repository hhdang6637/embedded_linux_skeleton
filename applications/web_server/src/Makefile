CFLAGS += -lfcgi -lapp

BIN=web_handler
SRCS=main.o simplewebfactory.o fcgi.cpp simplewebfactory_url_html_map.o simplewebfactory_url_js_map.o system_manager_js.o \
firmware_manager_js.o syslog_js.o openvpn_js.o time_ntp_js.o

ifeq ($(MODEL),$(filter $(MODEL),pi_3_b orange_pi_zero))
SRCS += wifisetting_js.o
endif
SRCS += MPFDParser/Exception.o MPFDParser/Field.o MPFDParser/Parser.o

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
