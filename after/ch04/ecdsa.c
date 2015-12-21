#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "hex.h"
#include "sha.h"
#include "digest.h"
#include "huge.h"
#include "ecdsa.h"

void ecdsa_sign( elliptic_curve *params, 
         huge *private_key,
         unsigned int *hash, 
         int hash_len, 
         dsa_signature *signature )
{
  unsigned char K[] = {
    0x9E, 0x56, 0xF5, 0x09, 0x19, 0x67, 0x84, 0xD9, 0x63, 0xD1, 0xC0, 
    0xA4, 0x01, 0x51, 0x0E, 0xE7, 0xAD, 0xA3, 0xDC, 0xC5, 0xDE, 0xE0, 
    0x4B, 0x15, 0x4B, 0xF6, 0x1A, 0xF1, 0xD5, 0xA6, 0xDE, 0xCE
  };
  huge k;
  point X;
  huge z;

  // This should be a random number between 0 and n-1
  load_huge( &k, ( unsigned char * ) K, sizeof( K ) );

  set_huge( &X.x, 0 );
  set_huge( &X.y, 0 );
  copy_huge( &X.x, &params->G.x );
  copy_huge( &X.y, &params->G.y );

  multiply_point( &X, &k, &params->a, &params->p );

  set_huge( &signature->r, 0 );
  copy_huge( &signature->r, &X.x );
  divide( &signature->r, &params->n, NULL ); // r = x1 % n

  // z is the L_n leftmost bits of hash - cannot be longer than n
  load_huge( &z, ( unsigned char * ) hash,
     ( ( hash_len * 4 ) < params->n.size ) ? ( hash_len * 4 ) : params->n.size );

  // s = k^-1 ( z + r d_a ) % n
  inv( &k, &params->n );
  set_huge( &signature->s, 0 );
  copy_huge( &signature->s, private_key );
  multiply( &signature->s, &signature->r );
  add( &signature->s, &z );
  multiply( &signature->s, &k );
  divide( &signature->s, &params->n, NULL );

  free_huge( &k );
  free_huge( &z );
  free_huge( &X.x );
  free_huge( &X.y );
}

int ecdsa_verify( elliptic_curve *params,
         point *public_key,
         unsigned int *hash,
         int hash_len,
         dsa_signature *signature )
{
  huge z;
  huge w;
  point G;
  point Q;
  int match;

  // w = s^-1 % n
  set_huge( &w, 0 );
  copy_huge( &w, &signature->s );
  inv( &w, &params->n );

  // z is the L_n leftmost bits of hash - cannot be longer than n
  load_huge( &z, ( unsigned char * ) hash, 
   ( ( hash_len * 4 ) < params->n.size ) ? ( hash_len * 4 ) : params->n.size );

  // u1 = zw % n
  multiply( &z, &w );
  divide( &z, &params->n, NULL );  // u1 = z

  // u2 = (rw) % q
  multiply( &w, &signature->r );
  divide( &w, &params->n, NULL ); // u2 = w

  // (x1,y1) = u1 * G + u2 * Q
  set_huge( &G.x, 0 );
  set_huge( &G.y, 0 );
  set_huge( &Q.x, 0 );
  set_huge( &Q.y, 0 );
  copy_huge( &G.x, &params->G.x );
  copy_huge( &G.y, &params->G.y );
  copy_huge( &Q.x, &public_key->x );
  copy_huge( &Q.y, &public_key->y ); 

  multiply_point( &G, &z, &params->a, &params->p );
  multiply_point( &Q, &w, &params->a, &params->p );
  add_points( &G, &Q, &params->p );
 
  // r = x1 % n
  divide( &G.x, &params->n, NULL );

  match = !compare( &G.x, &signature->r );

  free_huge( &z );
  free_huge( &w );
  free_huge( &G.x );
  free_huge( &G.y );
  free_huge( &Q.x );
  free_huge( &Q.y );

  return match;
}

#ifdef TEST_ECDSA
int main( int argc, char *argv[ ] )
{
  // ECC parameters
  unsigned char P[] = { 
 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
  };
  unsigned char b[] = { 
  0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 
  0x98, 0x86,  0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 
  0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
  };
  unsigned char q[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
  0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 
  0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
  };
  unsigned char gx[] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 
    0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 
    0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
  };
  unsigned char gy[] = { 
  0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 
  0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 
  0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
  };

  // key
  unsigned char w[] = { 0xDC, 0x51, 0xD3, 0x86, 0x6A, 0x15, 0xBA, 0xCD, 0xE3, 
  0x3D, 0x96, 0xF9, 0x92, 0xFC, 0xA9, 0x9D, 0xA7, 0xE6, 0xEF, 0x09, 0x34, 0xE7, 
  0x09, 0x75, 0x59, 0xC2, 0x7F, 0x16, 0x14, 0xC8, 0x8A, 0x7F };

  elliptic_curve curve;
  ecc_key A;
  dsa_signature signature;

  digest_ctx ctx;

  load_huge( &curve.p, ( unsigned char * ) P, sizeof( P ) );
  set_huge( &curve.a, 3 );
  curve.a.sign = 1;
  load_huge( &curve.b, b, sizeof( b ) );
  load_huge( &curve.G.x, gx, sizeof( gx ) );
  load_huge( &curve.G.y, gy, sizeof( gy ) );
  load_huge( &curve.n, q, sizeof( q ) );

  // Generate new public key from private key “w” and point “G”
  load_huge( &A.d, w, sizeof( w ) );
  set_huge( &A.Q.x, 0 );
  set_huge( &A.Q.y, 0 );
  copy_huge( &A.Q.x, &curve.G.x );
  copy_huge( &A.Q.y, &curve.G.y );
  multiply_point( &A.Q, &A.d, &curve.a, &curve.p );

  new_sha256_digest( &ctx );
  update_digest( &ctx, "abc", 3 );
  finalize_digest( &ctx );

  ecdsa_sign( &curve, &A.d, ctx.hash, ctx.hash_len, &signature );

  printf( "R:" );
  show_hex( signature.r.rep, signature.r.size );
  printf( "S:" );
  show_hex( signature.s.rep, signature.r.size );

  if ( !ecdsa_verify( &curve, &A.Q, ctx.hash, ctx.hash_len, &signature ) )
  {
    printf( "Signatures don't match.\n" );
  }
  else
  {
    printf( "Signature verified.\n" );
  }

  return 0;
}
#endif

/*
jdavies@localhost$ ./ecdsa
R:
cb28e0999b9c7715fd0a80d8e47a77079716cbbf917dd72e97566ea1c066957c
S:
86fa3bb4e26cad5bf90b7f81899256ce7594bb1ea0c89212748bff3b3d5b0315
Verifying
Signature verified.
*/
