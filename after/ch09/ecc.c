#include <stdlib.h>
#include <string.h>
#include "huge.h"
#include "ecc.h"

unsigned char prime192v1_P[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
unsigned char prime192v1_A[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};
unsigned char prime192v1_B[] = {
  0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7,
  0x0F, 0xA7, 0xE9, 0xAB, 0x72, 0x24, 0x30, 0x49,
  0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1
};
unsigned char prime192v1_Gx[] = {
  0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6,
  0x7C, 0xBF, 0x20, 0xEB, 0x43, 0xA1, 0x88, 0x00,
  0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12
};
unsigned char prime192v1_Gy[] = {
  0x07, 0x19, 0x2B, 0x95, 0xFF, 0xC8, 0xDA, 0x78,
  0x63, 0x10, 0x11, 0xED, 0x6B, 0x24, 0xCD, 0xD5,
  0x73, 0xF9, 0x77, 0xA1, 0x1E, 0x79, 0x48, 0x11
};
unsigned char prime192v1_N[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0x99, 0xDE, 0xF8, 0x36,
  0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31
};

unsigned char prime256v1_P[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
unsigned char prime256v1_A[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};
unsigned char prime256v1_B[] = {
  0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
  0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
  0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
  0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};
unsigned char prime256v1_Gx[] = {
  0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
  0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
  0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
  0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
};
unsigned char prime256v1_Gy[] = {
  0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
  0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
  0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
  0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};
unsigned char prime256v1_N[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
  0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

int get_named_curve( const char *curve_name, elliptic_curve *target )
{
  if ( !strcmp( "prime192v1", curve_name ) ||
      !strcmp( "secp192r1", curve_name ) )
  {
    load_huge( &target->p, prime192v1_P, sizeof( prime192v1_P ) );
    load_huge( &target->a, prime192v1_A, sizeof( prime192v1_A ) );
    load_huge( &target->b, prime192v1_B, sizeof( prime192v1_B ) );
    load_huge( &target->G.x, prime192v1_Gx, 
      sizeof( prime192v1_Gx ) );
    load_huge( &target->G.y, prime192v1_Gy,
      sizeof( prime192v1_Gy ) );
    load_huge( &target->n, prime192v1_N, sizeof( prime192v1_N ) );
    
    return 0;
  }
  else if ( !strcmp( "prime256v1", curve_name ) ||
            !strcmp( "secp256r1", curve_name ) )
  {
    load_huge( &target->p, prime256v1_P, sizeof( prime256v1_P ) );
    load_huge( &target->a, prime256v1_A, sizeof( prime256v1_A ) );
    load_huge( &target->b, prime256v1_B, sizeof( prime256v1_B ) );
    load_huge( &target->G.x, prime256v1_Gx,
      sizeof( prime256v1_Gx ) );
    load_huge( &target->G.y, prime256v1_Gy,
      sizeof( prime256v1_Gy ) );
    load_huge( &target->n, prime256v1_N, sizeof( prime256v1_N ) );

    return 0;
  }

  // Unsupported named curve

  return 1;
}

void add_points( point *p1, point *p2, huge *p )
{
  point p3;
  huge denominator;
  huge numerator;
  huge invdenom;
  huge lambda;

  set_huge( &denominator, 0 ); 
  copy_huge( &denominator, &p2->x );    // denominator = x2
  subtract( &denominator, &p1->x );     // denominator = x2 - x1
  set_huge( &numerator, 0 );
  copy_huge( &numerator, &p2->y );      // numerator = y2
  subtract( &numerator, &p1->y );       // numerator = y2 - y1
  set_huge( &invdenom, 0 );
  copy_huge( &invdenom, &denominator );
  inv( &invdenom, p );
  set_huge( &lambda, 0 );
  copy_huge( &lambda, &numerator );
  multiply( &lambda, &invdenom );       // lambda = numerator / denominator
  set_huge( &p3.x, 0 );
  copy_huge( &p3.x, &lambda );    // x3 = lambda
  multiply( &p3.x, &lambda );     // x3 = lambda * lambda
  subtract( &p3.x, &p1->x );      // x3 = ( lambda * lambda ) - x1
  subtract( &p3.x, &p2->x );      // x3 = ( lambda * lambda ) - x1 - x2

  divide( &p3.x, p, NULL );       // x3 = ( ( lamdba * lambda ) - x1 - x2 ) % p

  // positive remainder always
  if ( p3.x.sign ) 
  {
    p3.x.sign = 0;
    subtract( &p3.x, p );
    p3.x.sign = 0;
  }

  set_huge( &p3.y, 0 );
  copy_huge( &p3.y, &p1->x );    // y3 = x1
  subtract( &p3.y, &p3.x );      // y3 = x1 - x3
  multiply( &p3.y, &lambda );    // y3 = ( x1 - x3 ) * lambda
  subtract( &p3.y, &p1->y );     // y3 = ( ( x1 - x3 ) * lambda ) - y

  divide( &p3.y, p, NULL );
  // positive remainder always
  if ( p3.y.sign )
  {
    p3.y.sign = 0;
    subtract( &p3.y, p );
    p3.y.sign = 0;
  }

  // p1->x = p3.x
  // p1->y = p3.y
  copy_huge( &p1->x, &p3.x );
  copy_huge( &p1->y, &p3.y );

  free_huge( &p3.x );
  free_huge( &p3.y );
  free_huge( &denominator );
  free_huge( &numerator );
  free_huge( &invdenom );
  free_huge( &lambda );
}

static void double_point( point *p1, huge *a, huge *p )
{
  huge lambda;
  huge l1;
  huge x1;
  huge y1;

  set_huge( &lambda, 0 );
  set_huge( &x1, 0 );
  set_huge( &y1, 0 );
  set_huge( &lambda, 2 );     // lambda = 2;
  multiply( &lambda, &p1->y );  // lambda = 2 * y1
  inv( &lambda, p );       // lambda = ( 2 * y1 ) ^ -1 (% p)

  set_huge( &l1, 3 );       // l1 = 3
  multiply( &l1, &p1->x );    // l1 = 3 * x
  multiply( &l1, &p1->x );    // l1 = 3 * x ^ 2
  add( &l1, a );         // l1 = ( 3 * x ^ 2 ) + a
  multiply( &lambda, &l1 );    // lambda = [ ( 3 * x ^ 2 ) + a ] / [ 2 * y1 ] ) % p
  copy_huge( &y1, &p1->y );
  // Note - make two copies of x2; this one is for y1 below
  copy_huge( &p1->y, &p1->x );
  set_huge( &x1, 2 );
  multiply( &x1, &p1->x );    // x1 = 2 * x1

  copy_huge( &p1->x, &lambda );  // x1 = lambda
  multiply( &p1->x, &lambda );  // x1 = ( lambda ^ 2 );
  subtract( &p1->x, &x1 );    // x1 = ( lambda ^ 2 ) - ( 2 * x1 )
  divide( &p1->x, p, NULL );   // [ x1 = ( lambda ^ 2 ) - ( 2 * x1 ) ] % p
  
  if ( p1->x.sign )
  {
    subtract( &p1->x, p );
    p1->x.sign = 0;
    subtract( &p1->x, p );
  }
  subtract( &p1->y, &p1->x );  // y3 = x3 – x1
  multiply( &p1->y, &lambda ); // y3 = lambda * ( x3 - x1 );
  subtract( &p1->y, &y1 );   // y3 = ( lambda * ( x3 - x1 ) ) - y1
  divide( &p1->y, p, NULL );  // y3 = [ ( lambda * ( x3 - x1 ) ) - y1 ] % p
  if ( p1->y.sign )
  {
    p1->y.sign = 0;
    subtract( &p1->y, p );
    p1->y.sign = 0;
  }

  free_huge( &lambda );
  free_huge( &x1 );
  free_huge( &y1 );
  free_huge( &l1 );
}

void multiply_point( point *p1, huge *k, huge *a, huge *p )
{
  int i;
  unsigned char mask;
  point dp;
  int paf = 1;

  set_huge( &dp.x, 0 );
  set_huge( &dp.y, 0 );
  copy_huge( &dp.x, &p1->x );
  copy_huge( &dp.y, &p1->y );
  for ( i = k->size; i; i-- )
  {
    for ( mask = 0x01; mask; mask <<= 1 )
    {
      if ( k->rep[ i - 1 ] & mask )
      {
       if ( paf )
       {
         paf = 0;
         copy_huge( &p1->x, &dp.x );
         copy_huge( &p1->y, &dp.y );
       }
       else
       {
         add_points( p1, &dp, p );
       }
     }
     // double dp
     double_point( &dp, a, p );
    }
  } 

  free_huge( &dp.x );
  free_huge( &dp.y );
}
