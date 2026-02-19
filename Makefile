CC = gcc
CFLAGS = -Wall -Wextra -pedantic

caesar:
	$(CC) main.c -o caesar

lib:
	$(CC) $(CFLAGS) -shared caesar.c -o libcaesar.so

install: 
	sudo cp libcaesar.so /usr/local/lib/
