# CC       = gcc
CXXFLAGS += -fPIC -I.

SHARED=libapp.so
SRCS=simpleTimerSync.o
SRCS += cpu_stat.o
SRCS += rpc/rpcMessage.o rpc/rpcMessageAddr.o rpc/rpcUnixClient.o rpc/rpcUnixServer.o
SRCS += rpc/rpcMessageCpuHistory.o

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))

$(SHARED): $(OBJS)
	$(CXX) -shared $(CXXFLAGS) $(OBJS) -o $(SHARED)

clean:
	rm -f $(OBJS) $(SHARED)

install:
	cp *.h       $(ROOTFS_DIR)/usr/include
	cp rpc/*.h       $(ROOTFS_DIR)/usr/include
	cp $(SHARED) $(ROOTFS_DIR)/usr/lib

all: $(SHARED) install
