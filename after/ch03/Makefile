all: rsa

OPTS = -g -Wall -Wno-pointer-sign

rsa: rsa.c rsa.h huge.c huge.h ../ch02/hex.c ../ch02/hex.h 
	gcc -I../ch02 -DTEST_RSA -o rsa $(OPTS) rsa.c huge.c ../ch02/hex.c

clean:
	rm -f rsa
	rm -f core
	rm -f core.*
