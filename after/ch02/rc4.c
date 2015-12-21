#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rc4.h"
#include "hex.h"

static void rc4_operate( const unsigned char *plaintext,
             int plaintext_len,
             unsigned char *ciphertext,
             const unsigned char *key,
             int key_len,
             rc4_state *state )
{
  int i, j;
  unsigned char *S;
  unsigned char tmp;

  i = state->i;
  j = state->j;
  S = state->S;

  // KSA (key scheduling algorithm)
  if ( S[ 0 ] == 0 && S[ 1 ] == 0 )
  {
    for ( i = 0; i < 256; i++ )
    {
      S[ i ] = i;
    }
    j = 0;
    for ( i = 0; i < 256; i++ )
    {
      j = ( j + S[ i ] + key[ i % key_len ] ) % 256;
      tmp = S[ i ];
      S[ i ] = S[ j ];
      S[ j ] = tmp; 
    }
    i = 0;
    j = 0;
  }

  while ( plaintext_len-- )
  {
    i = ( i + 1 ) % 256;
    j = ( j + S[ i ] ) % 256;
    tmp = S[ i ];
    S[ i ] = S[ j ];
    S[ j ] = tmp;
    *(ciphertext++) = S[ ( S[ i ] + S[ j ] ) % 256 ] ^ *(plaintext++);
  }

  state->i = i;
  state->j = j;
}

void rc4_40_encrypt( const unsigned char *plaintext, 
           const int plaintext_len,
           unsigned char ciphertext[], 
           void *state,
           const unsigned char *key )
{
  rc4_operate( plaintext, plaintext_len, ciphertext, key, 5, 
   ( rc4_state * ) state );
}

void rc4_40_decrypt( const unsigned char *ciphertext, 
           const int ciphertext_len,
           unsigned char plaintext[], 
           void *state,
           const unsigned char *key )
{
  rc4_operate( ciphertext, ciphertext_len, plaintext, key, 5, 
   ( rc4_state * ) state );
}

void rc4_128_encrypt( const unsigned char *plaintext, 
           const int plaintext_len,
           unsigned char ciphertext[], 
           void *state,
           const unsigned char *key )
{
  rc4_operate( plaintext, plaintext_len, ciphertext, key, 16, 
   ( rc4_state * ) state );
}

void rc4_128_decrypt( const unsigned char *ciphertext, 
           const int ciphertext_len,
           unsigned char plaintext[], 
           void *state,
           const unsigned char *key )
{
  rc4_operate( ciphertext, ciphertext_len, plaintext, key, 16, 
   ( rc4_state * ) state );
}

#ifdef TEST_RC4
int main( int argc, char *argv[ ] )
{
  unsigned char *key;
  unsigned char *input;
  unsigned char *output;
  int key_len;
  int input_len;
  rc4_state state;

  if ( argc < 4 )
  {
    fprintf( stderr, "Usage: %s [-e|-d] <key> <input>\n", argv[ 0 ] );
    exit( 0 );
  }

  key_len = hex_decode( argv[ 2 ], &key );
  input_len = hex_decode( argv[ 3 ], &input );

  output = malloc( input_len );
  state.S[ 0 ] = 0;
  state.S[ 1 ] = 0;
  rc4_operate( input, input_len, output, key, key_len, &state );
  printf( "Results: " );
  show_hex( output, input_len );

  free( key );
  free( input );

  return 0;
}
#endif

/*
[jdavies@localhost ssl]$ ./rc4 -e abcdef abcdefghijklmnop
Results: daf70b86e76454eb975e3bfe2cce339c
*/
