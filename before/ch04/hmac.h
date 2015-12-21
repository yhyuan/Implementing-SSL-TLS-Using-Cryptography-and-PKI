#ifndef HMAC_H
#define HMAC_H

void hmac( const unsigned char *key, 
     int key_length, 
     const unsigned char *text, 
     int text_length,
    digest_ctx *digest );
    /*
     void (*hash_block_operate)(const unsigned char *input, unsigned int hash[] ),
     void (*hash_block_finalize)(unsigned char *block, int length ),
     int hash_block_length,
     int hash_code_length,
     unsigned int *hash_out );
     */

#endif
