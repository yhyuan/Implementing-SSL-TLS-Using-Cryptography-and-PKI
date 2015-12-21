#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "digest.h"
#include "md5.h"
#include "sha.h"
#include "hex.h"

/**
 * Generic digest hash computation. The hash should be set to its initial
 * value *before* calling this function.
 */
int digest_hash( unsigned char *input, 
                 int len, 
                 unsigned int *hash, 
                 void (*block_operate)(const unsigned char *input, 
                 unsigned int hash[] ),
                 void (*block_finalize)(unsigned char *block, int length ) )
{
  unsigned char padded_block[ DIGEST_BLOCK_SIZE ];
  int length_in_bits = len * 8;

  while ( len >= INPUT_BLOCK_SIZE )
  {
    // Special handling for blocks between 56 and 64 bytes
    // (not enough room for the 8 bytes of length, but also
    // not enough to fill up a block)
    if ( len < DIGEST_BLOCK_SIZE )
    {
     memset( padded_block, 0, sizeof( padded_block ) );
     memcpy( padded_block, input, len );
     padded_block[ len ] = 0x80;
     block_operate( padded_block, hash );

     input += len;
     len = -1;
   }
   else
   {
     block_operate( input, hash );

     input += DIGEST_BLOCK_SIZE;
     len -= DIGEST_BLOCK_SIZE;
   }
  }

  memset( padded_block, 0, sizeof( padded_block ) );
  if ( len >= 0 )
  {
    memcpy( padded_block, input, len );
    padded_block[ len ] = 0x80;
  }

  block_finalize( padded_block, length_in_bits );

  block_operate( padded_block, hash );

  return 0;
}

void update_digest( digest_ctx *context, const unsigned char *input, int input_len )
{
  context->input_len += input_len;

  // Process any left over from the last call to "update_digest"
  if ( context->block_len > 0 )
  {
    // How much we need to make a full block
    int borrow_amt = DIGEST_BLOCK_SIZE - context->block_len;

    if ( input_len < borrow_amt )
    {
      memcpy( context->block + context->block_len, input, input_len );
      context->block_len += input_len;
      input_len = 0;
    }
    else
    {
      memcpy( context->block + context->block_len, input, borrow_amt );
      context->block_operate( context->block, context->hash );
      context->block_len = 0;
      input += borrow_amt;
      input_len -= borrow_amt;
   }
 }

  while ( input_len >= DIGEST_BLOCK_SIZE )
  {
  context->block_operate( input, context->hash );

    input += DIGEST_BLOCK_SIZE;
    input_len -= DIGEST_BLOCK_SIZE;
  }

  // Have some non-aligned data left over; save it for next call, or
  // "finalize" call.
  if ( input_len > 0 )
  {
    memcpy( context->block, input, input_len );
    context->block_len = input_len;
  }
}

/**
 * Process whatever's left over in the context buffer, append
 * the length in bits, and update the hash one last time.
 */
void finalize_digest( digest_ctx *context )
{
  memset( context->block + context->block_len, 0, DIGEST_BLOCK_SIZE -
    context->block_len );
  context->block[ context->block_len ] = 0x80;
  // special handling if the last block is < 64 but > 56
  if ( context->block_len >= INPUT_BLOCK_SIZE )
  {
    context->block_operate( context->block, context->hash );
    context->block_len = 0;
  memset( context->block + context->block_len, 0, DIGEST_BLOCK_SIZE -
    context->block_len );
  }
  // Only append the length for the very last block
  // Technically, this allows for 64 bits of length, but since we can only
  // process 32 bits worth, we leave the upper four bytes empty
  context->block_finalize( context->block, context->input_len * 8 );

  context->block_operate( context->block, context->hash );
}

#ifdef TEST_DIGEST
int main( int argc, char *argv[ ] )
{
  unsigned int *hash;
  int hash_len;
  int i;
  unsigned char *decoded_input;
  int decoded_len;

  if ( argc < 3 )
  {
    fprintf( stderr, "Usage: %s [-md5|-sha] [0x]<input>\n", argv[ 0 ] );
    exit( 0 );
  }

  decoded_len = hex_decode( argv[ 2 ], &decoded_input );

  if ( !( strcmp( argv[ 1 ], "-md5" ) ) )
  {
    hash = malloc( sizeof( int ) * MD5_RESULT_SIZE );
    memcpy( hash, md5_initial_hash, sizeof( int ) * MD5_RESULT_SIZE );
    hash_len = MD5_RESULT_SIZE;
    digest_hash( decoded_input, decoded_len, hash,
      md5_block_operate, md5_finalize );
  }
  else if ( !( strcmp( argv[ 1 ], "-sha1" ) ) )
  {
    hash = malloc( sizeof( int ) * SHA1_RESULT_SIZE );
    memcpy( hash, sha1_initial_hash, sizeof( int ) * SHA1_RESULT_SIZE );
    hash_len = SHA1_RESULT_SIZE;
    digest_hash( decoded_input, decoded_len, hash,
      sha1_block_operate, sha1_finalize );
  }
  else
  {
    fprintf( stderr, "unsupported digest algorithm '%s'\n", argv[ 1 ] );
    exit( 0 );
  }

  {
    unsigned char *display_hash = ( unsigned char * ) hash;
 
    for ( i = 0; i < ( hash_len * 4 ); i++ )
    {
      printf( "%.02x", display_hash[ i ] );
    }
     printf( "\n" );
  }

  free( hash );
  free( decoded_input );

  return 0;
}
#endif

/*
jdavies@localhost$ digest -md5 abc
900150983cd24fb0d6963f7d28e17f72

jdavies@localhost$ digest -sha1 abc
a9993e364706816aba3e25717850c26c9cd0d89d
*/
