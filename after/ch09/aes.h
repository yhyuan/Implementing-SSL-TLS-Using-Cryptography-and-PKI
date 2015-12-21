#ifndef AES_H
#define AES_H

void aes_128_encrypt( const unsigned char *plaintext,
           const int plaintext_len,
           unsigned char ciphertext[],
           void *iv,
           const unsigned char *key );
void aes_128_decrypt( const unsigned char *ciphertext,
           const int ciphertext_len,
           unsigned char plaintext[],
           void *iv,
           const unsigned char *key );
void aes_256_encrypt( const unsigned char *plaintext,
           const int plaintext_len,
           unsigned char ciphertext[],
           void *iv,
           const unsigned char *key );
void aes_256_decrypt( const unsigned char *ciphertext,
           const int ciphertext_len,
           unsigned char plaintext[],
           void *iv,
           const unsigned char *key );
int aes_ccm_encrypt( const unsigned char *input,
                     int input_len,
                     const unsigned char *addldata,
                     const int addldata_len,
                     unsigned char *output,
                     void *iv,
                     const unsigned char *key );
int aes_ccm_decrypt( const unsigned char *input,
                     int input_len,
                     const unsigned char *addldata,
                     const int addldata_len,
                     unsigned char *output,
                     void *iv,
                     const unsigned char *key );
int aes_gcm_encrypt( const unsigned char *input,
                     int input_len,
                     const unsigned char *addldata,
                     const int addldata_len,
                     unsigned char *output,
                     void *iv,
                     const unsigned char *key );
int aes_gcm_decrypt( const unsigned char *input,
                     int input_len,
                     const unsigned char *addldata,
                     const int addldata_len,
                     unsigned char *output,
                     void *iv,
                     const unsigned char *key );

#endif
