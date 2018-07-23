# CC       = gcc
CXXFLAGS += -fPIC

SHARED=libapp.so
SRCS=rpc_unix.o simpleTimerSync.o

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
