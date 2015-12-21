all: asn1 x509

OPTS = -g -Wall -Wno-pointer-sign

asn1: asn1.c asn1.h ../ch01/base64.c ../ch01/base64.h
	gcc -I../ch01 -DTEST_ASN1 $(OPTS) -o asn1 asn1.c ../ch01/base64.c

x509: x509.c x509.h asn1.c asn1.h ../ch01/base64.c ../ch01/base64.h ../ch02/hex.c ../ch02/hex.h ../ch03/huge.c ../ch03/huge.h ../ch03/rsa.c ../ch03/rsa.h ../ch04/dsa.c ../ch04/dsa.h ../ch04/digest.c ../ch04/digest.h ../ch04/md5.c ../ch04/md5.h ../ch04/sha.c ../ch04/sha.h
	gcc -I../ch01 -I../ch02 -I../ch03 -I../ch04 -DTEST_X509 $(OPTS) -o x509 x509.c asn1.c ../ch01/base64.c ../ch02/hex.c ../ch03/huge.c ../ch03/rsa.c ../ch04/dsa.c ../ch04/digest.c ../ch04/sha.c ../ch04/md5.c -lm

clean:
	rm -f asn1
	rm -f x509
	rm -f core
	rm -f core.*
