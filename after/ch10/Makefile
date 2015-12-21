all: https https_openssl

OPTS = -g -Wall -Wno-pointer-sign
INCLUDES=-I../ch08 -I../ch06 -I../ch01 -I../ch02 -I../ch03 -I../ch04 -I../ch05 -I../ch07
SOURCE_FILES=https.c \
../ch08/tls.c \
../ch02/aes.c \
../ch06/x509.c \
../ch06/prf.c \
../ch01/base64.c \
../ch02/hex.c \
../ch02/des.c \
../ch02/rc4.c \
../ch03/huge.c \
../ch04/dsa.c \
../ch04/md5.c \
../ch04/sha.c \
../ch04/hmac.c \
../ch04/digest.c \
../ch05/asn1.c \
../ch07/file.c \
../ch07/privkey.c \
../ch08/rsa.c
HEADER_FILES=../ch08/tls.h \
../ch02/aes.h \
../ch06/x509.h \
../ch06/prf.h \
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
../ch05/asn1.h \
../ch07/file.h \
../ch07/privkey.h \
../ch08/rsa.h

https: $(SOURCE_FILES) $(HEADER_FILES)
	gcc $(INCLUDES) $(OPTS) -o https $(SOURCE_FILES) -lm

OPENSSL_HOME=/usr/local/ssl/include

https_openssl: https_openssl.c ../ch01/base64.c ../ch01/base64.h ../ch02/hex.c ../ch02/hex.c
	gcc -I../ch01 -I../ch02 -I$(OPENSSL_HOME) $(OPTS) -o https_openssl https_openssl.c ../ch01/base64.c ../ch02/hex.c -lssl

clean:
	rm -f https
	rm -f https_openssl
	rm -f core
	rm -f core.*
