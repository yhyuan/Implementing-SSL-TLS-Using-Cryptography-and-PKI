#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif
#include "base64.h"
#include "ssl.h"

#define HTTPS_PORT 443

/**
 * Accept a well-formed URL (e.g. http://www.company.com/index.html) and return
 * pointers to the host part and the path part. Note that this function 
 * modifies the uri itself as well. It returns 0 on success, -1 if the URL is 
 * found to be malformed in any way.
 */
int parse_url( char *uri, char **host, char **path )
{
  char *pos;

  pos = strstr( uri, "//" );

  if ( !pos )
  {
    return -1;
  }

  *host = pos + 2;

  pos = strchr( *host, '/' );
 
  if ( !pos )
  {
    *path = NULL;
  }
  else
  {
    *pos = '\0';
    *path = pos + 1;
  }

  return 0;
}

#define MAX_GET_COMMAND 255
/**
 * Format and send an HTTP get command. The return value will be 0
 * on success, -1 on failure, with errno set appropriately. The caller
 * must then retrieve the response.
 */
int http_get( int connection, const char *path, const char *host,
       SSLParameters *ssl_context )
{
  static char get_command[ MAX_GET_COMMAND ];

  sprintf( get_command, "GET /%s HTTP/1.1\r\n", path );

  if ( ssl_send( connection, get_command, strlen( get_command ), 
                 0, ssl_context ) == -1 )
  {
    return -1;
  }

  sprintf( get_command, "Host: %s\r\n", host );
  if ( ssl_send( connection, get_command, strlen( get_command ), 
                 0, ssl_context ) == -1 )
  {
    return -1;
  }

  sprintf( get_command, "Connection: close\r\n\r\n" );
  if ( ssl_send( connection, get_command, strlen( get_command ), 
                 0, ssl_context ) == -1 )
  {
    return -1;
  }

  return 0;
}

#define BUFFER_SIZE 255

/**
 * Receive all data available on a connection and dump it to stdout
 */
void display_result( int connection, SSLParameters *ssl_context )
{
  int received = 0;
  static char recv_buf[ BUFFER_SIZE + 1 ];

  // Can't exit when return value is 0 like in http.c, since empty SSL 
  // messages can be sent (openssl does this)
  while ( ( received = ssl_recv( connection, recv_buf, BUFFER_SIZE, 
                                 0, ssl_context ) ) >= 0 )
  {
    recv_buf[ received ] = '\0';
    printf( "%s", recv_buf );
  }
  printf( "\n" );
}

#define HTTP_PORT    80

/**
 * Simple command-line HTTP client.
 */
int main( int argc, char *argv[ ] )
{
  int client_connection;
  char *host, *path;
  struct hostent *host_name;
  struct sockaddr_in host_address;
#ifdef WIN32
  WSADATA wsaData;
#endif
  SSLParameters ssl_context;

  if ( argc < 2 )
  {
    fprintf( stderr, 
      "Usage: %s: [-p http://[username:password@]proxy-host:proxy-port] <URL>\n", 
      argv[ 0 ] );
    return 1;
  }

  host = path = NULL;

  if ( parse_url( argv[ 1 ], &host, &path ) == -1 )
  {
    fprintf( stderr, "Error - malformed URL '%s'.\n", argv[ 1 ] );
    return 1;
  }

  printf( "Connecting to host '%s'\n", host );
  // Step 1: open a socket connection on http port with the destination host.
#ifdef WIN32
  if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != NO_ERROR )
  {
    fprintf( stderr, "Error, unable to initialize winsock.\n" );
    return 2;
  }
#endif

  client_connection = socket( PF_INET, SOCK_STREAM, 0 );

  if ( !client_connection )
  {
    perror( "Unable to create local socket" );
    return 2;
  }

  host_name = gethostbyname( host );

  if ( !host_name )
  {
    perror( "Error in name resolution" );
    return 3;
  }

  host_address.sin_family = AF_INET;
  host_address.sin_port = htons( HTTPS_PORT );
  memcpy( &host_address.sin_addr, host_name->h_addr_list[ 0 ], 
          sizeof( struct in_addr ) );

  if ( connect( client_connection, ( struct sockaddr * ) &host_address, 
       sizeof( host_address ) ) == -1 )
  {
    perror( "Unable to connect to host" );
    return 4;
  }

  if ( ssl_connect( client_connection, &ssl_context ) )
  {
    fprintf( stderr, "Error: unable to negotiate SSL connection.\n" );
    return 3;
  }

  printf( "Retrieving document: '%s'\n", path );
  http_get( client_connection, path, host, &ssl_context  );

  display_result( client_connection, &ssl_context  );

  printf( "Shutting down.\n" );

#ifdef WIN32
  if ( closesocket( client_connection ) == -1 )
#else
  if ( close( client_connection ) == -1 )
#endif
  {
    perror( "Error closing client connection" );
    return 5;
  }

#ifdef WIN32
  WSACleanup();
#endif

  return 0;
}
