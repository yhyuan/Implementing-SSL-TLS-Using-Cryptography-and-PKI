#ifndef ECC_H
#define ECC_H

typedef struct
{
  huge x;
  huge y;
}
point;

typedef struct
{
  huge p;
  huge a;
  huge b;
  point G;
  huge n; // n is prime and is the "order" of G
  huge h; // h = #E(F_p)/n (# is the number of points on the curve)
}
elliptic_curve;

typedef struct
{
  huge d;  // random integer < n; this is the private key
  point Q; // Q = d * G; this is the public key
}
ecc_key;

void add_points( point *p1, point *p2, huge *p );
void multiply_point( point *p1, huge *k, huge *a, huge *p );
int get_named_curve( const char *curve_name, elliptic_curve *target );

#endif
