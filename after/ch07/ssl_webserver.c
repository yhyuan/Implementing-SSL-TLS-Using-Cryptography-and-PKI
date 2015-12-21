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
#include "tls.h"

#define HTTP_PORT 80
#define HTTPS_PORT 8443
#define DEFAULT_LINE_LEN 255

char *read_line( int connection, TLSParameters *tls_context )
{
  static int line_len = DEFAULT_LINE_LEN;
  static char *line = NULL;
  int size;
  char c;    // must be c, not int
  int pos = 0;

  if ( !line )
  {
    line = malloc( line_len );
  }

  while ( ( size = tls_recv( connection, &c, 1, 0, tls_context ) ) >= 0 )
  {
    if ( ( c == '\n' ) && ( line[ pos - 1 ] == '\r' ) )
    {
      line[ pos - 1 ] = '\0';
      break;
    }
    line[ pos++ ] = c;

    if ( pos > line_len )
    {
      line_len *= 2;
      line = realloc( line, line_len );
    }
  }

  return line;
}

static void build_success_response( int connection, TLSParameters *tls_context )
{
  char buf[ 255 ];
  sprintf( buf, "HTTP/1.1 200 Success\r\nConnection: Close\r\n\
Content-Type:text/html\r\n\
\r\n<html><head><title>Test Page</title></head><body>Nothing here</body></html>\
\r\n" );

  // Technically, this should account for short writes.
  if ( tls_send( connection, buf, strlen( buf ), 0, tls_context ) < strlen( buf ) )
  {
    perror( "Trying to respond" );
  }
}

static void build_error_response( int connection, 
                                  int error_code, 
                                  TLSParameters *tls_context )
{
  char buf[ 255 ];
  sprintf( buf, "HTTP/1.1 %d Error Occurred\r\n\r\n", error_code );

  // Technically, this should account for short writes.
  if ( tls_send( connection, buf, strlen( buf ), 0, tls_context ) < strlen( buf ) )
  {
    perror( "Trying to respond" );
  }
}

static void process_https_request( int connection )

{
  char *request_line; 
  TLSParameters tls_context;

  if ( tls_accept( connection, &tls_context ) )
  {
    perror( "Unable to establish SSL connection" );
  } 
  else
  {
    request_line = read_line( connection, &tls_context );

    if ( strncmp( request_line, "GET", 3 ) )
    {
      // Only supports "GET" requests
      build_error_response( connection, 400, &tls_context );
    }
    else
    { 
      // Skip over all header lines, don't care
      while ( strcmp( read_line( connection, &tls_context ), "" ) )
      {
        printf( "skipped a header line\n" );
      }

      build_success_response( connection, &tls_context );
    }

    tls_shutdown( connection, &tls_context );
  }

#ifdef WIN32
  if ( closesocket( connection ) == -1 )
#else
  if ( close( connection ) == -1 )
#endif
  {
    perror( "Unable to close connection" );
  }
}

int main( int argc, char *argv[ ] )
{
  int listen_sock;
  int connect_sock;
  int on = 1;
  struct sockaddr_in local_addr;
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof( client_addr );
#ifdef WIN32
  WSADATA wsaData;
 
  if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != NO_ERROR )
  {
     perror( "Unable to initialize winsock" );
     exit( 0 );
  }
#endif

  if ( ( listen_sock = socket( PF_INET, SOCK_STREAM, 0 ) ) == -1 )
  {
    perror( "Unable to create listening socket" );
    exit( 0 );
  }

  if ( setsockopt( listen_sock, 
           SOL_SOCKET, 
           SO_REUSEADDR, 
           &on, sizeof( on ) ) == -1 )
  {
    perror( "Setting socket option" );
    exit( 0 );
  }

  local_addr.sin_family = AF_INET;
  local_addr.sin_port = htons( HTTPS_PORT );
  local_addr.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  //local_addr.sin_addr.s_addr = htonl( INADDR_ANY );

  if ( bind( listen_sock, 
        ( struct sockaddr * ) &local_addr, 
        sizeof( local_addr ) ) == -1 )
  {
    perror( "Unable to bind to local address" );
    exit( 0 );
  }
  
  if ( listen( listen_sock, 5 ) == -1 )
  {
    perror( "Unable to set socket backlog" );
    exit( 0 );
  }

  while ( ( connect_sock = accept( listen_sock, 
                   ( struct sockaddr * ) &client_addr, 
                   &client_addr_len ) ) != -1 )
  {
    // TODO: ideally, this would spawn a new thread.
    process_https_request( connect_sock );
  }

  if ( connect_sock == -1 )
  {
    perror( "Unable to accept socket" );
  }

  return 0;
}
