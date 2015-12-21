#ifndef RC4_H
#define RC4_H

#define RC4_STATE_ARRAY_LEN  256

typedef struct
{
  int i;
  int j;
  unsigned char S[ RC4_STATE_ARRAY_LEN ];
}
rc4_state;

void rc4_40_encrypt( const unsigned char *plaintext, 
           const int plaintext_len,
           unsigned char ciphertext[], 
           void *state,
           const unsigned char *key );
void rc4_40_decrypt( const unsigned char *ciphertext, 
           const int ciphertext_len,
           unsigned char plaintext[], 
           void *state,
           const unsigned char *key );
void rc4_128_encrypt( const unsigned char *plaintext, 
           const int plaintext_len,
           unsigned char ciphertext[], 
           void *state,
           const unsigned char *key );
void rc4_128_decrypt( const unsigned char *ciphertext, 
           const int ciphertext_len,
           unsigned char plaintext[], 
           void *state,
           const unsigned char *key );

#endif
