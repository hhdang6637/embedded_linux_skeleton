BIN=system_manager_daemon
SRCS=main.o system_manager.o serviceHiawatha.o firmwareManager.o userManager.o serviceNtp.o serviceOpenvpn.o
SRCS+=timeManager.o

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(BIN) -lapp

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/sbin

all: $(BIN) install
