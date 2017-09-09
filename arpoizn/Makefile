CC=gcc
CCOPT=-g -Wall
LDOPT=
ARPOIZN_H=arpoizn.h
ARPOIZN_C=arpoizn.c
ARPOIZN_BIN=arpoizn

all: arpoizn

$(ARPOIZN_BIN): $(ARPOIZN_C) $(ARPOIZN_H)
	$(CC) $(CCOPT) -c -o $(ARPOIZN_BIN).o $(ARPOIZN_C)
	$(CC) $(LDOPT) -o $(ARPOIZN_BIN) $(ARPOIZN_BIN).o

clean:
	rm $(ARPOIZN_BIN).o
	rm $(ARPOIZN_BIN)

