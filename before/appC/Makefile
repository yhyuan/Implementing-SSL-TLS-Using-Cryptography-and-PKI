all: https

OPTS = -g -Wall -Wno-pointer-sign

SOURCES = https.c \
ssl.c \
../ch01/base64.c \
../ch02/des.c \
../ch02/rc4.c \
../ch02/hex.c \
../ch03/rsa.c \
../ch03/huge.c \
../ch04/digest.c \
../ch04/md5.c \
../ch04/sha.c \
../ch04/dsa.c \
../ch05/asn1.c \
../ch05/x509.c
HEADERS = ssl.h \
../ch01/base64.h \
../ch02/des.h \
../ch02/rc4.h \
../ch02/hex.h \
../ch03/rsa.h \
../ch03/huge.h \
../ch04/digest.h \
../ch04/md5.h \
../ch04/sha.h \
../ch04/dsa.h \
../ch05/asn1.h \
../ch05/x509.h

https: $(SOURCES) $(HEADERS)
	gcc -I../ch01 -I../ch02 -I../ch03 -I../ch04 -I../ch05 -o https $(OPTS) $(SOURCES) -lm

clean:
	rm -f https
	rm -f core
	rm -f core.*
