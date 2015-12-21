#ifndef ECC_INT_H
#define ECC_INT_H

typedef struct 
{ 
  int x; 
  int y; 
} 
point; 

typedef struct 
{ 
  int private_key; 
  point public_key; 
} 
key_pair; 

/** 
 * Describe y^2 = (x^3 + ax + b) % p 
 */ 
typedef struct 
{ 
  int p; 
  int a; 
  int b; 
  point G;  // base point 
} 
domain_parameters;

#endif
