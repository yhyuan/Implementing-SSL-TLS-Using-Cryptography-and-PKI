#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "digest.h"
#include "hex.h"
#include "hmac.h"
#include "md5.h"
#include "sha.h"
#include "prf.h"

/**
 * P_MD5 or P_SHA, depending on the value of the “new_digest” function
 * pointer.
 * HMAC_hash( secret, A(1) + seed ) + HMAC_hash( secret, A(2) + seed ) + ...
 * where + indicates concatenation and A(0) = seed, A(i) = 
 * HMAC_hash( secret, A(i - 1) )
 */
static void P_hash( const unsigned char *secret,
                    int secret_len,
                    const unsigned char *seed,
                    int seed_len,
                    unsigned char *output,
                    int out_len,
                    void (*new_digest)( digest_ctx *context ) )
{
  unsigned char *A;
  int hash_len; // length of the hash code in bytes
  digest_ctx A_ctx, h;
  int adv;
  int i;
  new_digest( &A_ctx );
  hmac( secret, secret_len, seed, seed_len, &A_ctx );

  hash_len = A_ctx.hash_len * sizeof( int );
  A = malloc( hash_len + seed_len );
  memcpy( A, A_ctx.hash, hash_len );
  memcpy( A + hash_len, seed, seed_len );

  i = 2;

  while ( out_len > 0 )
  {
    new_digest( &h );
    // HMAC_Hash( secret, A(i) + seed )
    hmac( secret, secret_len, A, hash_len + seed_len, &h );
    adv = ( h.hash_len * sizeof( int ) ) < out_len ? 
       h.hash_len * sizeof( int ) : out_len;
    memcpy( output, h.hash, adv );
    out_len -= adv;
    output += adv;
    // Set A for next iteration
    // A(i) = HMAC_hash( secret, A(i-1) )
    new_digest( &A_ctx );
    hmac( secret, secret_len, A, hash_len, &A_ctx );
    memcpy( A, A_ctx.hash, hash_len );
  }

  free( A );
}

/**
 * P_MD5( S1, label + seed ) XOR P_SHA1(S2, label + seed );
 * where S1 & S2 are the first & last half of secret
 * and label is an ASCII string.  Ignore the null terminator.
 *
 * output must already be allocated.
 */
void PRF( const unsigned char *secret,
          int secret_len,
          const unsigned char *label,
          int label_len, 
          const unsigned char *seed,
          int seed_len,  
          unsigned char *output,
          int out_len ) 
{
  unsigned char *concat = ( unsigned char * ) malloc( label_len + seed_len );
  memcpy( concat, label, label_len );
  memcpy( concat + label_len, seed, seed_len );
  P_hash( secret, secret_len, concat, label_len + seed_len, output,
    out_len, new_sha256_digest );
    
  free( concat );
}

#ifdef TEST_PRF
int main( int argc, char *argv[ ] )
{
  unsigned char *output;
  int out_len, i;
  int secret_len;
  int label_len;
  int seed_len;
  unsigned char *secret;
  unsigned char *label;
  unsigned char *seed;

  if ( argc < 5 )
  {
    fprintf( stderr, 
      "usage: %s [0x]<secret> [0x]<label> [0x]<seed> <output len>\n", 
      argv[ 0 ] );
    exit( 0 );
  }

  secret_len = hex_decode( argv[ 1 ], &secret );
  label_len = hex_decode( argv[ 2 ], &label );
  seed_len = hex_decode( argv[ 3 ], &seed );
  out_len = atoi( argv[ 4 ] );
  output = ( unsigned char * ) malloc( out_len );
  
  PRF( secret, secret_len,
       label, label_len,
       seed, seed_len,
       output, out_len );

  for ( i = 0; i < out_len; i++ )
  {
    printf( "%.02x", output[ i ] );
  } 
  printf( "\n" );
  
  free( secret );
  free( label );
  free( seed );
  free( output );
  
  return 0;
} 
#endif

/*
[jdavies@localhost ssl]$ ./prf secret label seed 20
b5baf4722b91851a8816d22ebd8c1d8cc2e94d55
*/
