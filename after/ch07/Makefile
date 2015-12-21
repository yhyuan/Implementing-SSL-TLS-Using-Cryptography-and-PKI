all: privkey ssl_webserver

OPTS = -g -Wall -Wno-pointer-sign

privkey: privkey.c privkey.h file.c file.h ../ch01/base64.c ../ch01/base64.h ../ch02/hex.c ../ch02/hex.h ../ch02/des.c ../ch02/des.h ../ch03/huge.c ../ch03/huge.h ../ch03/rsa.c ../ch03/rsa.h ../ch04/digest.c ../ch04/digest.h ../ch04/md5.c ../ch04/md5.h ../ch04/sha.c ../ch04/sha.c ../ch05/asn1.c ../ch05/asn1.h
	gcc -I../ch01 -I../ch02 -I../ch03 -I../ch05 -DTEST_PRIVKEY $(INCLUDES) $(OPTS) -o privkey privkey.c file.c ../ch01/base64.c ../ch02/hex.c ../ch02/des.c ../ch03/huge.c ../ch03/rsa.c ../ch04/digest.c ../ch04/md5.c ../ch04/sha.c ../ch05/asn1.c -lm

INCLUDES=-I../ch01 -I../ch02 -I../ch03 -I../ch04 -I../ch06 -I../ch05
SOURCE_FILES=ssl_webserver.c \
tls.c \
privkey.c \
file.c \
../ch06/prf.c \
../ch06/x509.c \
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
privkey.h \
file.h \
../ch06/x509.h \
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

ssl_webserver: $(SOURCE_FILES) $(HEADER_FILES)
	gcc $(INCLUDES) $(OPTS) -o ssl_webserver $(SOURCE_FILES) -lm

clean:
	rm -f privkey
	rm -f ssl_webserver
	rm -f core
	rm -f core.*
