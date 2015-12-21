#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file.h"
#ifdef WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

/**
 * Read a whole file into memory and return a pointer to that memory chunk,
 * or NULL if something went wrong.  Caller must free the allocated memory.
 */
char *load_file_into_memory( char *filename, int *buffer_length )
{
  int file;
  struct stat file_stat;
  char *buffer, *bufptr;
  int buffer_size;
  int bytes_read;

  if ( ( file = open( filename, O_RDONLY ) ) == -1 )
  {
    perror( "Unable to open file" );
    return NULL;
  }

  // Slurp the whole thing into memory
  if ( fstat( file, &file_stat ) )
  {
    perror( "Unable to stat certificate file" );
    return NULL;
  }

  buffer_size = file_stat.st_size;

  buffer = ( char * ) malloc( buffer_size );

  if ( !buffer )
  {
    perror( "Not enough memory" );
    return NULL;
  }

  bufptr = buffer;

  while ( ( bytes_read = read( file, ( void * ) buffer, buffer_size ) ) )
  {
    bufptr += bytes_read;
  }

  close( file );

  if ( buffer_length != NULL )
  {
    *buffer_length = buffer_size;
  }

  return buffer;
}
