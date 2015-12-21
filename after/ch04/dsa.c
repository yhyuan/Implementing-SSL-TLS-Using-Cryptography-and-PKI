#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha.h"
#include "hex.h"
#include "digest.h"
#include "dsa.h"

static void generate_message_secret( dsa_params *params, huge *k )
{  
  int i;
  huge q;
  huge one;

  set_huge( &q, 0 ); // initialize this so that copy works
  set_huge( &one, 1 );

  copy_huge( &q, &params->q );
  subtract( &q, &one );

  // XXX the extra + 8 aren't really necessary since we're not generating
  // a random "c"
  k->sign = 0;
  k->size = params->q.size + 8;
  k->rep = malloc( k->size );
  // TODO this should be filled with random bytes
  for ( i = 0; i < k->size; i++ )
  {
    k->rep[ i ] = i + 1;
  }

  // k will become k % ( q - 1 );
  divide( k, &q, NULL );
  add( k, &one );
}

void dsa_sign( dsa_params *params,
       huge *private_key,
       unsigned int *hash,
       int hash_len, 
       dsa_signature *signature )
{
  huge k;
  huge z; 
  huge q;
 
  set_huge( &q, 1 );
 
  generate_message_secret( params, &k );
  // r = ( g ^ k % p ) % q
  mod_pow( &params->g, &k, &params->p, &signature->r );
  copy_huge( &q, &params->q );
  divide( &signature->r, &q, NULL );

  // z = hash(message), only approved with SHA
  load_huge( &z, ( unsigned char * ) hash,
   ( (hash_len * 4 ) < params->q.size ) ? 
   (hash_len * 4 ) : params->q.size );
  
  // s = ( inv(k) * ( z + xr ) ) % q
  inv( &k, &params->q );
  set_huge( &signature->s, 0 );
  copy_huge( &signature->s, private_key );
  multiply( &signature->s, &signature->r );
  add( &signature->s, &z );
  multiply( &signature->s, &k );
  copy_huge( &q, &params->q );
  divide( &signature->s, &q, NULL );

  free_huge( &z );
}

int dsa_verify( dsa_params *params,
                huge *public_key,
                unsigned int *hash,
                int hash_len,
                dsa_signature *signature )
{
  int match;
  huge w, z, u1, u2, q, p;

  set_huge( &q, 1 );
  set_huge( &p, 1 );
  set_huge( &w, 0 );

  // w = inv(s) % q
  copy_huge( &w, &signature->s );
  inv( &w, &params->q );

  // z = hash(message), truncated to sizeof(q)
  load_huge( &z, ( unsigned char * ) hash,
   ( (hash_len * 4 ) < params->q.size ) ? 
   (hash_len * 4 ) : params->q.size );

  // u1 = (zw) % q
  multiply( &z, &w );
  copy_huge( &q, &params->q );
  divide( &z, &params->q, NULL );  // u1 = z

  // u2 = (rw) % q
  multiply( &w, &signature->r );
  copy_huge( &q, &params->q );
  divide( &w, &q, NULL ); // u2 = w

  // v = ( ( ( g^u1) % p * (y^u2) %p ) % p ) % q
  mod_pow( &params->g, &z, &params->p, &u1 );
  mod_pow( public_key, &w, &params->p, &u2 );
  multiply( &u1, &u2 );
  copy_huge( &p, &params->p );
  divide( &u1, &p, NULL );
  copy_huge( &q, &params->q );
  divide( &u1, &q, NULL ); // u1 is "v" now

  // Check to see if v & s match
  match = !compare( &u1, &signature->r );

  free_huge( &w );
  free_huge( &z );
  free_huge( &u1 );
  free_huge( &u2 );
  
  return match;
}

#ifdef TEST_DSA
int main( int argc, char *argv[] )
{
  unsigned char priv[] = {
    0x53, 0x61, 0xae, 0x4f, 0x6f, 0x25, 0x98, 0xde, 0xc4, 0xbf, 0x0b, 0xbe, 0x09, 
  0x5f, 0xdf,  0x90, 0x2f, 0x4c, 0x8e, 0x09 };
  unsigned char pub[] = {
    0x1b, 0x91, 0x4c, 0xa9, 0x73, 0xdc, 0x06, 0x0d, 0x21, 0xc6, 0xff, 0xab, 0xf6, 
  0xad, 0xf4, 0x11, 0x97, 0xaf, 0x23, 0x48, 0x50, 0xa8, 0xf3, 0xdb, 0x2e, 0xe6, 
  0x27, 0x8c, 0x40, 0x4c,  0xb3, 0xc8, 0xfe, 0x79, 0x7e, 0x89, 0x48, 0x90, 0x27, 
  0x92, 0x6f, 0x5b, 0xc5, 0xe6, 0x8f,  0x91, 0x4c, 0xe9, 0x4f, 0xed, 0x0d, 0x3c, 
  0x17, 0x09, 0xeb, 0x97, 0xac, 0x29, 0x77, 0xd5,  0x19, 0xe7, 0x4d, 0x17 };
  unsigned char P[] = {
    0x00, 0x9c, 0x4c, 0xaa, 0x76, 0x31, 0x2e, 0x71, 0x4d, 0x31, 0xd6, 0xe4, 0xd7, 
  0xe9, 0xa7,  0x29, 0x7b, 0x7f, 0x05, 0xee, 0xfd, 0xca, 0x35, 0x14, 0x1e, 0x9f, 
  0xe5, 0xc0, 0x2a, 0xe0,  0x12, 0xd9, 0xc4, 0xc0, 0xde, 0xcc, 0x66, 0x96, 0x2f, 
  0xf1, 0x8f, 0x1a, 0xe1, 0xe8, 0xbf,  0xc2, 0x29, 0x0d, 0x27, 0x07, 0x48, 0xb9, 
  0x71, 0x04, 0xec, 0xc7, 0xf4, 0x16, 0x2e, 0x50,  0x8d, 0x67, 0x14, 0x84, 0x7b };
  unsigned char Q[] = {
    0x00, 0xac, 0x6f, 0xc1, 0x37, 0xef, 0x16, 0x74, 0x52, 0x6a, 0xeb, 0xc5, 0xf8, 
  0xf2, 0x1f,  0x53, 0xf4, 0x0f, 0xe0, 0x51, 0x5f };
  unsigned char G[] = {
    0x7d, 0xcd, 0x66, 0x81, 0x61, 0x52, 0x21, 0x10, 0xf7, 0xa0, 0x83, 0x4c, 0x5f, 
  0xc8, 0x84,  0xca, 0xe8, 0x8a, 0x9b, 0x9f, 0x19, 0x14, 0x8c, 0x7d, 0xd0, 0xee, 
  0x33, 0xce, 0xb4, 0x57,  0x2d, 0x5e, 0x78, 0x3f, 0x06, 0xd7, 0xb3, 0xd6, 0x40, 
  0x70, 0x2e, 0xb6, 0x12, 0x3f, 0x4a,  0x61, 0x38, 0xae, 0x72, 0x12, 0xfb, 0x77, 
  0xde, 0x53, 0xb3, 0xa1, 0x99, 0xd8, 0xa8, 0x19,  0x96, 0xf7, 0x7f, 0x99 };
  dsa_params params;
  dsa_signature signature;
  huge x, y;
  unsigned char *msg = "abc123";
  digest_ctx ctx;

  // TODO load these from a DSA private key file instead
  load_huge( &params.g, G, sizeof( G ) );
  load_huge( &params.p, P, sizeof( P ) );
  load_huge( &params.q, Q, sizeof( Q ) );
  load_huge( &x, priv, sizeof( priv ) );
  load_huge( &y, pub, sizeof( pub ) );

  new_sha1_digest( &ctx );
  update_digest( &ctx, msg, strlen( msg ) );
  finalize_digest( &ctx );

  dsa_sign( &params, &x, ctx.hash, ctx.hash_len, &signature );

  printf( "DSA signature of abc123 is:" );
  printf( "r:" );
  show_hex( signature.r.rep, signature.r.size );
  printf( "s:" );
  show_hex( signature.s.rep, signature.s.size );
 
  if ( dsa_verify( &params, &y, ctx.hash, ctx.hash_len, &signature ) )
  {
    printf( "Verified\n" );
  }
  else
  {
    printf( "Verificiation failed\n" );
  }

  free_huge( &x );
  free_huge( &y );

  return 0;
}
#endif

/*
jdavies@localhost$ ./dsa
DSA signature of abc123 is:
r: 14297f2522458d809b6c5752d3975a00bb0d89e0
s: 2f6e24ed330faf27700470cc6074552e58cbea3a
Verifying:
Verified
*/
