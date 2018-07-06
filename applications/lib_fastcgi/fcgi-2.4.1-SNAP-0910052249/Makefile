export CFLAGS =-Wall

$(BIN):
	@rm -rf build
	@mkdir build
	@cd build && ../configure --host=arm && make ARCH=arm

install:

all: $(BIN)

clean:
	@rm -rf build
