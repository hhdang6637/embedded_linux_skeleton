CC = gcc
CFLAGS = -Wall -Wextra
LFLAGS = -lpthread

.PHONY: clean

all: status

status.o: status.c
	${CC} ${CFLAGS} -c status.c

status: status.o
	${CC} ${CFLAGS} status.o -o status ${LFLAGS}
	strip status

clean:
	rm -f *.o status
