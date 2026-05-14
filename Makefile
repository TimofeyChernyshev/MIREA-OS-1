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

test_secure_copy: test_secure_copy.c secure_copy.h caesar.h
	$(CC) $(CFLAGS) -c secure_copy.c -o secure_copy_no_main.o -DNO_MAIN
	$(CC) $(CFLAGS) test_secure_copy.c secure_copy_no_main.o -L. -lcaesar -pthread -o test_secure_copy
	./test_secure_copy
	rm -f test_secure_copy
	rm -f secure_copy_no_main.o