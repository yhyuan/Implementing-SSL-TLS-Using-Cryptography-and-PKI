all: des aes rc4

OPTS = -g -Wall -Wno-pointer-sign

des: des.c des.h hex.c hex.h
	gcc -DTEST_DES -o des $(OPTS) des.c hex.c

aes: aes.c aes.h hex.c hex.h
	gcc -DTEST_AES -o aes $(OPTS) aes.c hex.c

rc4: rc4.c rc4.h hex.c hex.h
	gcc -DTEST_RC4 -o rc4 $(OPTS) rc4.c hex.c

clean:
	rm -f des
	rm -f aes
	rm -f rc4
	rm -f core
	rm -f core.*
