BIN=cloud_cam

SRCS=main.o cloud_cam.o

# CXXFLAGS =-Wall -I$(BUILDROOT_BUILD_DIR)/build/opencv-2.4.13/modules/gpu/include
# CXXFLAGS +=-D$(MODEL) -I$(INCLUDE) -L$(LIB)

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
