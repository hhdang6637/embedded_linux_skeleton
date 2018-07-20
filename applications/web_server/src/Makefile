INCLUDE = $(ROOTFS_DIR)/usr/local/include/
LIB     = $(ROOTFS_DIR)/usr/local/lib

CFLAGS += -Wall -g -I$(INCLUDE) -L$(LIB) -lfcgi

BIN=web_handler
SRCS=main.o simplewebfactory.o
SRCS_HTML=footer.ohtml header.ohtml navbar.ohtml

%.o : %.cpp
	$(CXX) $< $(CFLAGS) -c -o $@

%.ohtml : %.html
	$(LD) -r -b binary -o $@ $<

OBJS   = $(patsubst %.cpp,%.o,$(SRCS))
OBJS   += $(patsubst %.html,%.ohtml,$(SRCS_HTML))

$(BIN): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/bin

all: $(BIN) install
