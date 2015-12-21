all: prf https

OPTS = -g -Wall -Wno-pointer-sign

prf: prf.c prf.h ../ch04/hmac.c ../ch04/hmac.h ../ch04/md5.c ../ch04/md5.h ../ch04/sha.c ../ch04/sha.h ../ch04/digest.c ../ch04/digest.h ../ch02/hex.c ../ch02/hex.h
	gcc -I../ch04 -I../ch02 -DTEST_PRF $(INCLUDES) $(OPTS) -o prf prf.c ../ch04/hmac.c ../ch04/md5.c ../ch04/sha.c ../ch04/digest.c ../ch02/hex.c ../ch02/hex.h -lm

INCLUDES=-I../ch01 -I../ch02 -I../ch03 -I../ch04 -I../ch05
SOURCE_FILES=https.c \
tls.c \
prf.c \
x509.c \
../ch01/base64.c \
../ch02/hex.c \
../ch02/des.c \
../ch02/rc4.c \
../ch02/aes.c \
../ch03/huge.c \
../ch03/rsa.c \
../ch04/dsa.c \
../ch04/md5.c \
../ch04/sha.c \
../ch04/hmac.c \
../ch04/digest.c \
../ch05/asn1.c
HEADER_FILES=tls.h \
x509.h \
../ch01/base64.h \
../ch02/hex.h \
../ch02/des.h \
../ch02/rc4.h \
../ch02/aes.h \
../ch03/huge.h \
../ch03/rsa.h \
../ch04/dsa.h \
../ch04/md5.h \
../ch04/sha.h \
../ch04/hmac.h \
../ch04/digest.h \
../ch05/asn1.h

https: $(SOURCE_FILES) $(HEADER_FILES)
	gcc $(INCLUDES) $(OPTS) -o https $(SOURCE_FILES) -lm

clean:
	rm -f prf
	rm -f https
	rm -f core
	rm -f core.*
