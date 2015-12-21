#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "sha.h"
#include "md5.h"
#include "hex.h"
#include "digest.h"
#include "hmac.h"

/**
 * Note: key_length, text_length, hash_block_length are in bytes.
 * hash_code_length is in ints.
 */
void hmac( const unsigned char *key, 
      int key_length, 
      const unsigned char *text, 
      int text_length,
      digest_ctx *digest )
      /*
      void (*hash_block_operate)(const unsigned char *input, unsigned int hash[] ),
      void (*hash_block_finalize)(unsigned char *block, int length ),
      int hash_block_length,
      int hash_code_length,
      unsigned int *hash_out )
      */
{
  unsigned char ipad[ DIGEST_BLOCK_SIZE ];
  unsigned char opad[ DIGEST_BLOCK_SIZE ];
  digest_ctx hash1;
  int i;

  // TODO if key_length > hash_block_length, should hash it using "hash_function"
  // first and then use that as the key.
  assert( key_length < DIGEST_BLOCK_SIZE );

  // "cheating"; copy the supplied digest context in here, since we don't
  // know which digest algorithm is being used
  memcpy( &hash1, digest, sizeof( digest_ctx ) );
  hash1.hash = ( unsigned int * ) malloc( 
  hash1.hash_len * sizeof( unsigned int ) );
  memcpy( hash1.hash, digest->hash, hash1.hash_len * sizeof( unsigned int ) );
 
  memset( ipad, 0x36, DIGEST_BLOCK_SIZE );

  for ( i = 0; i < key_length; i++ )
  {
    ipad[ i ] ^= key[ i ];
  }

  update_digest( &hash1, ipad, DIGEST_BLOCK_SIZE );
  update_digest( &hash1, text, text_length );
  finalize_digest( &hash1 );

  memset( opad, 0x5C, DIGEST_BLOCK_SIZE );

  for ( i = 0; i < key_length; i++ )
  {
    opad[ i ] ^= key[ i ];
  }

  update_digest( digest, opad, DIGEST_BLOCK_SIZE );
  update_digest( digest, ( unsigned char * ) hash1.hash, 
  hash1.hash_len * sizeof( int ) );
  finalize_digest( digest );

  free( hash1.hash );
}

#ifdef TEST_HMAC
int main( int argc, char *argv[ ] )
{
  int i;
  digest_ctx digest;
  int key_len;
  unsigned char *key;
  int text_len;
  unsigned char *text;

  if ( argc < 4 )
  {
    fprintf( stderr, "usage: %s [-sha1|md5] [0x]<key> [0x]<text>\n", argv[ 0 ] );
    exit( 0 );
  }

  if ( !( strcmp( argv[ 1 ], "-sha1" ) ) )
  {
    new_sha1_digest( &digest );
  }
  else if ( !( strcmp( argv[ 1 ], "-md5" ) ) )
  {
    new_md5_digest( &digest );
  }
  else
  {
    fprintf( stderr, "usage: %s [-sha1|md5] <key> <text>\n", argv[ 0 ] );
    exit( 1 );
  }

  key_len = hex_decode( argv[ 2 ], &key );
  text_len = hex_decode( argv[ 3 ], &text );

  hmac( key, key_len, text, text_len, &digest );

  for ( i = 0; i < digest.hash_len * sizeof( int ); i++ )
  {
    printf( "%.02x", ( ( unsigned char *) digest.hash )[ i ] );
  }
  printf( "\n" );

  free( digest.hash );
  free( key );
  free( text );

  return 0;
}
#endif

/*
jdavies@localhost$ hmac -md5 Jefe "what do ya want for nothing?"
750c783e6ab0b503eaa86e310a5db738
*/
