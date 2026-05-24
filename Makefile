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

lib_rc4: rc4.c rc4.h
	$(CC) $(CFLAGS) -shared rc4.c -o librc4.so
	
rc4: main.c librc4.so
	$(CC) main.c -o rc4

install_rc4:
	sudo cp librc4.so /usr/local/lib/

secure_copy_rc4: secure_copy.c rc4.c
	$(CC) secure_copy.c rc4.c -o secure_copy -pthread -Wall

test: libcaesar.so
	python3 test_caesar.py

test_secure_copy: test_secure_copy.c secure_copy.h rc4.h
	$(CC) $(CFLAGS) -c secure_copy.c -o secure_copy_no_main.o -DNO_MAIN
	$(CC) $(CFLAGS) test_secure_copy.c secure_copy_no_main.o rc4.c -pthread -o test_secure_copy
	./test_secure_copy
	rm -f test_secure_copy
	rm -f secure_copy_no_main.o