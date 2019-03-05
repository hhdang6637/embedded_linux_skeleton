BIN=cloud_cam

SRCS=main.o mqtt_client.o nmap_scan.o

CXXFLAGS =-Wall -I$(BUILDROOT_BUILD_DIR)/build/opencv-2.4.13/modules/gpu/include

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(BIN) -lopencv_core -lopencv_highgui -lpaho-mqtt3c

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/bin

all: $(BIN) install
