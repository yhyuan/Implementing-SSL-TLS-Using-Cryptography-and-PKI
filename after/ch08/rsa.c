#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"
#include "hex.h"

/**
 * Compute c = m^e mod n.
 */
void rsa_compute( huge *m, huge *e, huge *n, huge *c )
{
  huge counter;
  huge one;

  copy_huge( c, m );
  set_huge( &counter, 1 );
  set_huge( &one, 1 );
  while ( compare( &counter, e ) < 0 )
  {
    multiply( c, m );
    add( &counter, &one );
  }

  divide( c, n, NULL );

  free_huge( &counter );
  free_huge( &one );
  // Remainder (result) is now in c
}

/**
 * The input should be broken up into n-bit blocks, where n is the
 * length in bits of the modulus. The output will always be n bits
 * or less. Per RFC 2313, there must be at least 8 bytes of padding
 * to prevent an attacker from trying all possible padding bytes.
 *
 * output will be allocated by this routine, must be freed by the
 * caller.
 *
 * returns the length of the data encrypted in output
 */
int rsa_process( unsigned char *input,
                 unsigned int len,
                 unsigned char **output,
                 rsa_key *public_key,
                 unsigned char block_type )
{
  int i;
  huge c, m;
  int modulus_length = public_key->modulus->size;
  int block_size;
  unsigned char *padded_block = ( unsigned char * ) 
    malloc( modulus_length );
  int encrypted_size = 0;

  *output = NULL;

  while ( len )
  {
    encrypted_size += modulus_length;
    block_size = ( len < modulus_length - 11 ) ? 
      len : ( modulus_length - 11 );
    memset( padded_block, 0, modulus_length );
    memcpy( padded_block + ( modulus_length - block_size ), 
      input, block_size );
    // set block type
    padded_block[ 1 ] = block_type;

    for ( i = 2; i < ( modulus_length - block_size - 1 ); i++ )
    {
      if ( block_type == 0x02 )
      {
      // TODO make these random
      padded_block[ i ] = i;
      }
      else
      {
        padded_block[ i ] = 0xFF;
      }
    }
    
    load_huge( &m, padded_block, modulus_length );
    mod_pow( &m, public_key->exponent, public_key->modulus, &c );

    *output = ( unsigned char * ) realloc( *output, encrypted_size );

    unload_huge( &c, *output + ( encrypted_size - modulus_length ), 
      modulus_length );

    len -= block_size;
    input += block_size;
    free_huge( &m );
    free_huge( &c );
  } 
  
  free( padded_block );
  
  return encrypted_size;
}

int rsa_encrypt( unsigned char *input,
                 unsigned int len,
                 unsigned char **output,
                 rsa_key *public_key )
{
  return rsa_process( input, len, output, public_key, 0x02 );
} 
  
int rsa_sign( unsigned char *input, 
              unsigned int len,
              unsigned char **output,
              rsa_key *private_key )
{ 
  return rsa_process( input, len, output, private_key, 0x01 );
}

/**
 * Convert the input into key-length blocks and decrypt, unpadding
 * each time.
 * Return -1 if the input is not an even multiple of the key modulus
 * length or if the padding type is not “2”, otherwise return the
 * length of the decrypted data.
 */
int rsa_decrypt( unsigned char *input,
                 unsigned int len, 
                 unsigned char **output,
                 rsa_key *private_key )
{
  int i, out_len = 0;
  huge c, m;
  int modulus_length = private_key->modulus->size;
  unsigned char *padded_block = ( unsigned char * ) malloc( 
    modulus_length );
   
  *output = NULL;
  
  while ( len )
  {
    if ( len < modulus_length )
    {
      fprintf( stderr, "Error - input must be an even multiple \
        of key modulus %d (got %d)\n",
        private_key->modulus->size, len );
      free( padded_block );
      return -1;
    }
    
    load_huge( &c, input, modulus_length );
    mod_pow( &c, private_key->exponent, 
      private_key->modulus, &m );
    
    unload_huge( &m, padded_block, modulus_length );
    
    if ( padded_block[ 1 ] > 0x02 )
    {
      fprintf( stderr, "Decryption error or unrecognized block \
        type %d.\n", padded_block[ 1 ] );
      free_huge( &c ); 
      free_huge( &m );
      free( padded_block );
      return -1;
    }
    
    // Find next 0 byte after the padding type byte; this signifies
    // start-of-data
    i = 2;
    while ( padded_block[ i++ ] );
    
    out_len += modulus_length - i;
    *output = realloc( *output, out_len );
    memcpy( *output + ( out_len - ( modulus_length - i ) ),
      padded_block + i, modulus_length - i );
    
    len -= modulus_length;
    input += modulus_length;
    free_huge( &c );
    free_huge( &m );
  } 
  
  free( padded_block );
  
  return out_len;
} 

#ifdef TEST_RSA
const unsigned char TestModulus[] = {
0xC4, 0xF8, 0xE9, 0xE1, 0x5D, 0xCA, 0xDF, 0x2B, 
0x96, 0xC7, 0x63, 0xD9, 0x81, 0x00, 0x6A, 0x64, 
0x4F, 0xFB, 0x44, 0x15, 0x03, 0x0A, 0x16, 0xED, 
0x12, 0x83, 0x88, 0x33, 0x40, 0xF2, 0xAA, 0x0E, 
0x2B, 0xE2, 0xBE, 0x8F, 0xA6, 0x01, 0x50, 0xB9, 
0x04, 0x69, 0x65, 0x83, 0x7C, 0x3E, 0x7D, 0x15, 
0x1B, 0x7D, 0xE2, 0x37, 0xEB, 0xB9, 0x57, 0xC2, 
0x06, 0x63, 0x89, 0x82, 0x50, 0x70, 0x3B, 0x3F
};

const unsigned char TestPrivateKey[] = {
0x8a, 0x7e, 0x79, 0xf3, 0xfb, 0xfe, 0xa8, 0xeb, 
0xfd, 0x18, 0x35, 0x1c, 0xb9, 0x97, 0x91, 0x36, 
0xf7, 0x05, 0xb4, 0xd9, 0x11, 0x4a, 0x06, 0xd4, 
0xaa, 0x2f, 0xd1, 0x94, 0x38, 0x16, 0x67, 0x7a, 
0x53, 0x74, 0x66, 0x18, 0x46, 0xa3, 0x0c, 0x45, 
0xb3, 0x0a, 0x02, 0x4b, 0x4d, 0x22, 0xb1, 0x5a, 
0xb3, 0x23, 0x62, 0x2b, 0x2d, 0xe4, 0x7b, 0xa2, 
0x91, 0x15, 0xf0, 0x6e, 0xe4, 0x2c, 0x41
};

const unsigned char TestPublicKey[] = { 0x01, 0x00, 0x01 };

int main( int argc, char *argv[ ] )
{
  int exponent_len;
  int modulus_len;
  int data_len;
  unsigned char *exponent;
  unsigned char *modulus;
  unsigned char *data;
  rsa_key public_key;
  rsa_key private_key;

  if ( argc < 3 )
  {
    fprintf( stderr, "Usage: rsa [-e|-d] [<modulus> <exponent>] <data>\n" );
    exit( 0 );
  }
 
  if ( argc == 5 )
  {
    modulus_len = hex_decode( argv[ 2 ], &modulus );
    exponent_len = hex_decode( argv[ 3 ], &exponent );
    data_len = hex_decode( argv[ 4 ], &data );
  }
  else
  {
    data_len = hex_decode( argv[ 2 ], &data );
    modulus_len = sizeof( TestModulus );
    modulus = TestModulus;
    if ( !strcmp( "-e", argv[ 1 ] ) )
    {
      exponent_len = sizeof( TestPublicKey );
      exponent = TestPublicKey;
    }
    else
    {
      exponent_len = sizeof( TestPrivateKey );
      exponent = TestPrivateKey;
    }
  }

  public_key.modulus = ( huge * ) malloc( sizeof( huge ) );
  public_key.exponent = ( huge * ) malloc( sizeof( huge ) );
  private_key.modulus = ( huge * ) malloc( sizeof( huge ) );
  private_key.exponent = ( huge * ) malloc( sizeof( huge ) );

  if ( !strcmp( argv[ 1 ], "-e" ) )
  {
    unsigned char *encrypted;
    int encrypted_len;

    load_huge( public_key.modulus, modulus, modulus_len );
    load_huge( public_key.exponent, exponent, exponent_len );

    encrypted_len = rsa_encrypt( data, data_len, &encrypted, &public_key );
    show_hex( encrypted, encrypted_len );
    free( encrypted );
  }
  else if ( !strcmp( argv[ 1 ], "-d" ) )
  {
    int decrypted_len;
    unsigned char *decrypted;

    load_huge( private_key.modulus, modulus, modulus_len );
    load_huge( private_key.exponent, exponent, exponent_len );

    decrypted_len = rsa_decrypt( data, data_len, &decrypted, &private_key );
    
    show_hex( decrypted, decrypted_len );

    free( decrypted );
  }
  else
  {
    fprintf( stderr, "unrecognized option flag '%s'\n", argv[ 1 ] );
  }

  free( data );
  if ( argc == 5 )
  {
    free( modulus );
    free( exponent );
  }
}
#endif

/*
jdavies@localhost$ rsa -e abc
40f73315d3f74703904e51e1c72686801de06a55417110e56280f1f8471a3802406d2110011e1f38
7f7b4c43258b0a1eedc558a3aac5aa2d20cf5e0d65d80db3

jdavies@localhost$ rsa -d \ 0x40f73315d3f74703904e51e1c7\
2686801de06a55417110e56280f1f8471a3802406d2110011e1f387f\
7b4c43258b0a1eedc558a3aac5aa2d20cf5e0d65d80db3
616263
*/
