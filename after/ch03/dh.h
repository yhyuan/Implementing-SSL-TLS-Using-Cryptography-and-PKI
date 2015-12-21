#ifndef DH_H
#define DH_H

#include "huge.h"

typedef struct
{
  huge p;
  huge g;
  huge Y; // Ys for server or Yc for client
}
dh_key;

// There's no corresponding .c file for this header; Diffie-Hellman
// key exchange is accomplished entirely with huge.c's mod_pow.

#endif
