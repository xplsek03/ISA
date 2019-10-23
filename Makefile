CC=gcc 
CFLAGS=-Wall

all: dns
dns: dnsresolver.o
dnsresolver.o: dnsresolver.c functions.h

#clean:
#	rm -f dns dnsresolver.o
#run: program
#    ./program
