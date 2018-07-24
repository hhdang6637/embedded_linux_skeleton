CXXFLAGS += -g -lapp

BIN=hello_world
SRCS=main.o

%.o : %.cpp
	$(CXX) $< $(CXXFLAGS) -c -o $@

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))

$(BIN): $(OBJS)
	$(CXX) $(OBJS) $(CXXFLAGS) -o $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/bin

all: $(BIN) install
