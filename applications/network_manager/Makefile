CXXFLAGS += -lapp

BIN=network_manager_daemon
SRCS=main.o network_manager.o serviceDhcpC.o
ifeq ($(MODEL),pi_3_b)
SRCS+= serviceHostapd.o
endif
%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/sbin

all: $(BIN) install
