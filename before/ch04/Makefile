all: digest hmac dsa ecdsa

OPTS = -g -Wall -Wno-pointer-sign

digest: digest.c digest.h md5.c md5.h sha.c sha.h ../ch02/hex.c ../ch02/hex.h
	gcc -I../ch02 -DTEST_DIGEST $(OPTS) -o digest digest.c md5.c sha.c ../ch02/hex.c -lm

hmac: hmac.c hmac.h digest.c digest.h md5.c md5.h sha.c sha.c ../ch02/hex.c ../ch02/hex.h
	gcc -I../ch02 -DTEST_HMAC $(OPTS) -o hmac hmac.c digest.c md5.c sha.c ../ch02/hex.c -lm

dsa: dsa.c dsa.h sha.c sha.h digest.c digest.h ../ch03/huge.c ../ch03/huge.h ../ch02/hex.c ../ch02/hex.h
	gcc -I../ch03 -I../ch02 -DTEST_DSA $(OPTS) -o dsa dsa.c digest.c sha.c ../ch03/huge.c ../ch02/hex.c

ecdsa: ecdsa.c ecdsa.h ecc.c ecc.h dsa.h sha.c sha.h digest.c digest.h ../ch03/huge.h ../ch03/huge.c ../ch02/hex.c ../ch02/hex.h
	gcc -I../ch02 -I../ch03 -DTEST_ECDSA $(OPTS) -o ecdsa ecdsa.c ecc.c digest.c sha.c ../ch03/huge.c ../ch02/hex.c

clean:
	rm -f md5
	rm -f hmac
	rm -f digest
	rm -f dsa
	rm -f ecdsa
	rm -f core
	rm -f core.*
