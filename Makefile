CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC

all: lib caesar

lib: caesar.c caesar.h
	$(CC) $(CFLAGS) -shared caesar.c -o libcaesar.so

caesar: main.c libcaesar.so
	$(CC) main.c -o caesar

install: 
	sudo cp libcaesar.so /usr/local/lib/

test: libcaesar.so
	python3 test_caesar.py