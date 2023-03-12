CC = gcc
CFLAGS = -Wall

rpd: rpd.c
	$(CC) $(CFLAGS) rpd.c -o rpd

clean:
	rm -f rpd
