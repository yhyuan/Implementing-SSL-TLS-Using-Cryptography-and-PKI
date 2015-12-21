#ifndef SSL_H
#define SSL_H

#include "digest.h"
#include "x509.h"

int ssl_connect( int connection, SSLParameters *parameters );

int ssl_send( int connection, const char *application_data, int length, 
              int options, SSLParameters *parameters );

int ssl_recv( int connection, char *target_buffer, int buffer_size, 
              int options, SSLParameters *parameters );

#endif
