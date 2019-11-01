CC=gcc
CFLAGS=-I. -Werror -Wall -Wpedantic

build: dnsresolver.c functions.c
	$(CC) $(CFLAGS) dnsresolver.c functions.c functions.h -o dns


test:
	./tests.py
