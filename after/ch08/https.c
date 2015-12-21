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
#include "hex.h"
#include "tls.h"

#define HTTP_PORT       80
#define HTTPS_PORT      443

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

int parse_proxy_param( char *proxy_spec,
            char **proxy_host,
            int *proxy_port,
            char **proxy_user,
            char **proxy_password )
{
  char *login_sep, *colon_sep, *trailer_sep;
  // Technically, the user should start the proxy spec with
  // "http://". But, be forgiving if he didn't.
  if ( !strncmp( "http://", proxy_spec, 7 ) )
  {
   proxy_spec += 7;
  } 
  login_sep = strchr( proxy_spec, '@' );
 
  if ( login_sep )
  {
    colon_sep = strchr( proxy_spec, ':' );
    if ( !colon_sep || ( colon_sep > login_sep ) )
    {
      // Error - if username supplied, password must be supplied.
      fprintf( stderr, "Expected password in '%s'\n", proxy_spec );
      return 0;
    }
    *colon_sep = '\0';
    *proxy_user = proxy_spec;
    *login_sep = '\0';
    *proxy_password = colon_sep + 1;
    proxy_spec = login_sep + 1;
  }
  // If the user added a "/" on the end (as they sometimes do),
  // just ignore it.
  trailer_sep = strchr( proxy_spec, '/' );
  if ( trailer_sep )
  {
    *trailer_sep = '\0';
  }

  colon_sep = strchr( proxy_spec, ':' );
  if ( colon_sep )
  {
    // non-standard proxy port
    *colon_sep = '\0';
    *proxy_host = proxy_spec;
    *proxy_port = atoi( colon_sep + 1 );
    if ( *proxy_port == 0 )
    {
     // 0 is not a valid port; this is an error, whether
     // it was mistyped or specified as 0.
     return 0;
    }
  }
  else
  { 
    *proxy_port = HTTP_PORT;
    *proxy_host = proxy_spec;
  }
  return 1;
}

#define MAX_GET_COMMAND 255
/**
 * Format and send an HTTP get command. The return value will be 0
 * on success, -1 on failure, with errno set appropriately. The caller
 * must then retrieve the response.
 */
int http_get( int connection, const char *path, const char *host,
              TLSParameters *tls_context )
{
  static char get_command[ MAX_GET_COMMAND ];

  sprintf( get_command, "GET /%s HTTP/1.1\r\n", path );

  if ( tls_send( connection, get_command, 
       strlen( get_command ), 0, tls_context ) == -1 )
  {
    return -1;
  }

  sprintf( get_command, "Host: %s\r\n", host );
  if ( tls_send( connection, get_command, 
       strlen( get_command ), 0, tls_context ) == -1 )
  {
    return -1;
  }

  sprintf( get_command, "Connection: close\r\n\r\n" );
  if ( tls_send( connection, get_command, 
       strlen( get_command ), 0, tls_context ) == -1 )
  {
    return -1;
  }

  return 0;
}

#define BUFFER_SIZE 255

/**
 * Receive all data available on a connection and dump it to stdout
 */
void display_result( int connection, TLSParameters *tls_context )
{
  int received = 0;
  static char recv_buf[ BUFFER_SIZE + 1 ];

  while ( ( received = tls_recv( connection, recv_buf, 
            BUFFER_SIZE, 0, tls_context ) ) >= 0 )
  {
    recv_buf[ received ] = '\0';
    printf( "%s", recv_buf );
  }
  printf( "\n" );
}

/**
 * Simple command-line HTTP client.
 */
int main( int argc, char *argv[ ] )
{
  int client_connection;
  char *host, *path;
  char *proxy_host, *proxy_user, *proxy_password;
  int proxy_port;
  struct hostent *host_name;
  struct sockaddr_in host_address;
  int port = HTTPS_PORT;
  int ind;
  int master_secret_length;
  unsigned char *master_secret;
  int session_id_length;
  unsigned char *session_id;
#ifdef WIN32
  WSADATA wsaData;
#endif

  TLSParameters tls_context;

  if ( argc < 2 )
  {
    fprintf( stderr, 
      "Usage: %s: [-p http://[username:password@]proxy-host:proxy-port] <URL>\n", 
      argv[ 0 ] );
    return 1;
  }

  proxy_host = proxy_user = proxy_password = host = path = session_id = master_secret = NULL;
  session_id_length = master_secret_length = 0;

  for ( ind = 1; ind < ( argc - 1 ); ind++ )
  {
    if ( !strcmp( "-p", argv[ ind ] ) )
    {
      if ( !parse_proxy_param( argv[ ++ind ], &proxy_host, &proxy_port,
                               &proxy_user, &proxy_password ) )
      {
        fprintf( stderr, "Error - malformed proxy parameter '%s'.\n", argv[ 2 ] );
        return 2;
      }
    }
    else if ( !strcmp( "-s", argv[ ind ] ) )
    {
      session_id_length = hex_decode( argv[ ++ind ], &session_id );
    }
    else if ( !strcmp( "-m", argv[ ind ] ) )
    {
      master_secret_length = hex_decode( argv[ ++ind ], &master_secret );
    }
  }

  if ( ( ( master_secret_length > 0 ) && ( session_id_length == 0 ) ) ||
       ( ( master_secret_length == 0 ) && ( session_id_length > 0 ) ) )
  {
    fprintf( stderr, "session id and master secret must both be provided.\n" );
    return 3;
  }

  if ( parse_url( argv[ ind ], &host, &path ) == -1 )
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

  if ( proxy_host )
  {
    printf( "Connecting to host '%s'\n", proxy_host );
    host_name = gethostbyname( proxy_host );
  } 
  else
  {
    host_name = gethostbyname( host );
  }

  if ( !host_name )
  {
    perror( "Error in name resolution" );
    return 3;
  }

  host_address.sin_family = AF_INET;
  host_address.sin_port = htons( proxy_host ? proxy_port : HTTPS_PORT  );
  memcpy( &host_address.sin_addr, host_name->h_addr_list[ 0 ], 
          sizeof( struct in_addr ) );

  if ( connect( client_connection, ( struct sockaddr * ) &host_address, 
       sizeof( host_address ) ) == -1 )
  {
    perror( "Unable to connect to host" );
    return 4;
  }

  printf( "Connection complete; negotiating TLS parameters\n" );

  if ( session_id != NULL )
  {
    if ( tls_resume( client_connection, session_id_length,
         session_id, master_secret, &tls_context ) )
    {
      fprintf( stderr, "Error: unable to negotiate SSL connection.\n" );
      if ( close( client_connection ) == -1 )
      {
        perror( "Error closing client connection" );
        return 2;
      }
      return 3;
    }
  }
  else
  {
    if ( tls_connect( client_connection, &tls_context, 0 ) )
    {
      fprintf( stderr, "Error: unable to negotiate TLS connection.\n" );
      return 3;
    }
  }

  printf( "Retrieving document: '%s'\n", path );
  http_get( client_connection, path, host, &tls_context );

  display_result( client_connection, &tls_context );

  tls_shutdown( client_connection, &tls_context );

  printf( "Session ID was: " );
  show_hex( tls_context.session_id, tls_context.session_id_length );
  printf( "Master secret was: " );
  show_hex( tls_context.master_secret, MASTER_SECRET_LENGTH );

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

  if ( session_id != NULL )
  {
    free( session_id );
  } 
  
  if ( master_secret != NULL )
  {
    free( master_secret );
  } 

#ifdef WIN32
  WSACleanup();
#endif

  return 0;
}
