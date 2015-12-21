#ifndef PRIVKEY_H
#define PRIVKEY_H

#include "rsa.h"

int parse_private_key( rsa_key *privkey, 
                       const unsigned char *buffer, 
                       int buffer_length );
int parse_pkcs8_private_key( rsa_key *privkey, 
                             const unsigned char *buffer,
                             int buffer_length,
                             const unsigned char *passphrase );

#endif
