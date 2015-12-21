#ifndef ECDSA_H
#define ECDSA_H

#include "ecc.h"
#include "dsa.h"

void ecdsa_sign( elliptic_curve *params, 
         huge *private_key,
         unsigned int *hash, 
         int hash_len, 
         dsa_signature *signature );
int ecdsa_verify( elliptic_curve *params,
         point *public_key,
         unsigned int *hash,
         int hash_len,
         dsa_signature *signature );

#endif
