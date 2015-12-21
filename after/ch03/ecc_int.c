#include <stdio.h>
#include "ecc_int.h"

int ext_euclid( int z, int a )
{
  int i, j, y2, y1, y, quotient, remainder;

  i = a;
  j = z;
  y2 = 0;
  y1 = 1;

  while ( j > 0 )
  {
    quotient = i / j;
    remainder = i % j;
    y = y2  - ( y1 * quotient );
    i = j;
    j = remainder;
    y2 = y1;
    y1 = y;
  }
  return ( y2 % a );
}

/** 
 * Extended Euclidian algorithm to perform a modular inversion 
 * of x by y (e.g. (x/y) % p). 
 */ 
static int invert( int x, int y, int p ) 
{ 
  int inverse = ext_euclid( y, p ); 
  return x * inverse;
} 

static void add_points( point *p1, point *p2, int p ) 
{ 
  point p3; 
  int lambda = invert( p2->y - p1->y, p2->x - p1->x, p ); 
  
  p3.x = ( ( lambda * lambda ) - p1->x - p2->x ) % p; 
  p3.y = ( ( lambda * ( p1->x - p3.x ) ) - p1->y ) % p; 
  
  p1->x = p3.x; 
  p1->y = p3.y; 
} 

static void double_point( point *p1, int p, int a ) 
{ 
  point p3; 
  int lambda = invert( 3 * ( p1->x * p1->x ) + a, 2 * p1->y, p ); 
  p3.x = ( ( lambda * lambda ) - ( 2 * p1->x ) ) % p; 
  p3.y = ( ( lambda * ( p1->x - p3.x ) ) - p1->y ) % p; 

  p1->x = p3.x; 
  p1->y = p3.y; 
} 

static void multiply_point( point *p1, int k, int a, int p ) 
{ 
  point dp; 
  int mask; 
  int paf = 1; 

  dp.x = p1->x; 
  dp.y = p1->y; 

  for ( mask = 0x00000001; mask; mask <<= 1 ) 
  { 
    if ( mask & k ) 
    { 
      if ( paf ) 
      { 
        paf = 0; 
        p1->x = dp.x; 
        p1->y = dp.y; 
      } 
      else 
      { 
        add_points( p1, &dp, p ); 
      } 
    } 
    double_point( &dp, p, a ); 
  } 
} 
