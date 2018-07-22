# CC       = gcc
CFLAGS += -fPIC

SHARED=libipc.so.1
SRCS=rpc_unix.o

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))

$(SHARED): $(OBJS)
	$(CXX) -shared $(CXXFLAGS) $(OBJS) -o $(SHARED)

clean:
	rm -f $(OBJS) $(SHARED)

install:
	cp $(SHARED) $(ROOTFS_DIR)/usr/lib

all: $(SHARED) install
