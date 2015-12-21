all: aes https

OPTS = -g -Wall -Wno-pointer-sign

INCLUDES=-I../ch08 -I../ch06 -I../ch01 -I../ch02 -I../ch03 -I../ch04 -I../ch05 -I../ch07
SOURCE_FILES=../ch08/https.c \
tls.c \
aes.c \
x509.c \
ecc.c \
prf.c \
../ch01/base64.c \
../ch02/hex.c \
../ch02/des.c \
../ch02/rc4.c \
../ch03/huge.c \
../ch04/dsa.c \
../ch04/md5.c \
../ch04/sha.c \
../ch04/hmac.c \
../ch04/ecdsa.c \
../ch04/digest.c \
../ch05/asn1.c \
../ch07/file.c \
../ch07/privkey.c \
../ch08/rsa.c
HEADER_FILES=tls.h \
aes.h \
x509.h \
ecc.h \
prf.h \
../ch01/base64.h \
../ch02/hex.h \
../ch02/des.h \
../ch02/rc4.h \
../ch03/huge.h \
../ch04/dsa.h \
../ch04/md5.h \
../ch04/sha.h \
../ch04/hmac.h \
../ch04/digest.h \
../ch04/ecdsa.h \
../ch05/asn1.h \
../ch07/file.h \
../ch07/privkey.h \
../ch08/rsa.h

aes: aes.c aes.h ../ch02/hex.c ../ch02/hex.h
	gcc -DTEST_AES -I../ch02 $(OPTS) -o aes aes.c ../ch02/hex.c

https: $(SOURCE_FILES) $(HEADER_FILES)
	gcc $(INCLUDES) $(OPTS) -o https $(SOURCE_FILES) -lm

clean:
	rm -f https
	rm -f aes
	rm -f core
	rm -f core.*
