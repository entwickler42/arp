CC=gcc
CFLAGS=-g -Wall
LFLAGS=
OBJS=main.o

all: ${OBJS}
	${CC} ${LFLAGS} ${OBJS} -o sofoo

clean:
	rm ${OBJS}
	rm sofoo

main.o: main.c
	${CC} ${CFLAGS} -c main.c -o main.o
