# CC       = gcc
CXXFLAGS += -fPIC

SHARED=libapp.so
SRCS=simpleTimerSync.o rpcMessage.o rpcMessageAddr.o rpcUnixClient.o rpcUnixServer.o
SRCS += rpcMessageCpuHistory.o
SRCS += cpu_stat.o

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))

$(SHARED): $(OBJS)
	$(CXX) -shared $(CXXFLAGS) $(OBJS) -o $(SHARED)

clean:
	rm -f $(OBJS) $(SHARED)

install:
	cp *.h       $(ROOTFS_DIR)/usr/include
	cp $(SHARED) $(ROOTFS_DIR)/usr/lib

all: $(SHARED) install
