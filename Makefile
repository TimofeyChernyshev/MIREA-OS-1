CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC

all: lib caesar

lib: caesar.c caesar.h
	$(CC) $(CFLAGS) -shared caesar.c -o libcaesar.so

caesar: main.c libcaesar.so
	$(CC) main.c -o caesar

install: 
	sudo cp libcaesar.so /usr/local/lib/

secure_copy: secure_copy.c libcaesar.so queue.c
	$(CC) secure_copy.c -o secure_copy -L. -lcaesar -pthread queue.c -Wall

test: libcaesar.so
	python3 test_caesar.py
