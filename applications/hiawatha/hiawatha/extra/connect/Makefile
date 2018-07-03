CC = gcc
CFLAGS = -Wall -Wextra

.PHONY: clean

all: connect

connect.o: connect.c
	${CC} ${CFLAGS} -c connect.c

connect: connect.o
	${CC} ${CFLAGS} connect.o -o connect
	strip connect

clean:
	rm -f *.o connect
