#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include "md5.h"
#include "sha.h"
#include "digest.h"
#include "hmac.h"
#include "prf.h"
#include "des.h"
#include "rc4.h"
#include "aes.h"
#include "tls.h"

static CipherSuite suites[] =
{
  { TLS_NULL_WITH_NULL_NULL, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_RSA_WITH_NULL_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_RSA_WITH_NULL_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_RSA_EXPORT_WITH_RC4_40_MD5, 0, 0, 5, MD5_BYTE_SIZE, rc4_40_encrypt, rc4_40_decrypt, new_md5_digest },
  { TLS_RSA_WITH_RC4_128_MD5, 0, 0, 16, MD5_BYTE_SIZE, rc4_128_encrypt, rc4_128_decrypt, new_md5_digest },
  { TLS_RSA_WITH_RC4_128_SHA, 0, 0, 16, SHA1_BYTE_SIZE, rc4_128_encrypt, rc4_128_decrypt, new_sha1_digest },
  { TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_RSA_WITH_IDEA_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_RSA_WITH_DES_CBC_SHA, 8, 8, 8, SHA1_BYTE_SIZE, des_encrypt, des_decrypt, new_sha1_digest },
  { TLS_RSA_WITH_3DES_EDE_CBC_SHA, 8, 8, 24, SHA1_BYTE_SIZE, des3_encrypt, des3_decrypt, new_sha1_digest },
  { TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DH_DSS_WITH_DES_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, 8, 8, 24, SHA1_BYTE_SIZE, des3_encrypt, des3_decrypt, new_sha1_digest },
  { TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DH_RSA_WITH_DES_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DHE_DSS_WITH_DES_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DHE_RSA_WITH_DES_CBC_SHA, 8, 8, 8, SHA1_BYTE_SIZE, des_encrypt, des_decrypt, new_sha1_digest },
  { TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_DH_anon_WITH_RC4_128_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DH_anon_WITH_DES_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_DH_anon_WITH_3DES_EDE_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_KRB5_WITH_DES_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_KRB5_WITH_3DES_EDE_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_KRB5_WITH_RC4_128_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_KRB5_WITH_IDEA_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_KRB5_WITH_DES_CBC_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_KRB5_WITH_3DES_EDE_CBC_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_KRB5_WITH_RC4_128_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_KRB5_WITH_IDEA_CBC_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_KRB5_EXPORT_WITH_RC4_40_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_KRB5_EXPORT_WITH_RC4_40_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  // XXX are these three defined?
  { 0x002C, 0, 0, 0, 0, NULL, NULL, NULL },
  { 0x002D, 0, 0, 0, 0, NULL, NULL, NULL },
  { 0x002E, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_RSA_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt, aes_128_decrypt, new_sha1_digest },
  { TLS_DH_DSS_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt, aes_128_decrypt, new_sha1_digest },
  { TLS_DH_RSA_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt, aes_128_decrypt, new_sha1_digest },
  { TLS_DHE_DSS_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt, aes_128_decrypt, new_sha1_digest },
  { TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt, aes_128_decrypt, new_sha1_digest },
  { TLS_DH_anon_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt, aes_128_decrypt, new_sha1_digest },
  { TLS_RSA_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt, aes_256_decrypt, new_sha1_digest },
  { TLS_DH_DSS_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt, aes_256_decrypt, new_sha1_digest },
  { TLS_DH_RSA_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt, aes_256_decrypt, new_sha1_digest },
  { TLS_DHE_DSS_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt, aes_256_decrypt, new_sha1_digest },
  { TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt, aes_256_decrypt, new_sha1_digest },
  { TLS_DH_anon_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt, aes_256_decrypt, new_sha1_digest },
};

static void init_protection_parameters( ProtectionParameters *parameters )
{
  parameters->MAC_secret = NULL;
  parameters->key = NULL;
  parameters->IV = NULL;
  parameters->seq_num = 0;
  parameters->suite = TLS_NULL_WITH_NULL_NULL;
}
static void init_parameters( TLSParameters *parameters )
{
  init_protection_parameters( &parameters->pending_send_parameters );
  init_protection_parameters( &parameters->pending_recv_parameters );
  init_protection_parameters( &parameters->active_send_parameters );
  init_protection_parameters( &parameters->active_recv_parameters );

  memset( parameters->master_secret, '\0', MASTER_SECRET_LENGTH );
  memset( parameters->client_random, '\0', RANDOM_LENGTH );
  memset( parameters->server_random, '\0', RANDOM_LENGTH );
  parameters->server_hello_done = 0;
  parameters->server_finished = 0;

  parameters->unread_buffer = NULL;
  parameters->unread_length = 0;
}

/**
 * This is just like memcpy, except it returns a pointer to dest + n instead 
 * of dest, to simplify the process of repeated appends to a buffer.
 */
static char *append_buffer( char *dest, char *src, size_t n )
{
  memcpy( dest, src, n );
  return dest + n;
}

static char *read_buffer( char *dest, char *src, size_t n )
{
  memcpy( dest, src, n );
  return src + n;
}

static int send_message( int connection,
                         int content_type,
                         const unsigned char *content,
                         short content_len,
                         ProtectionParameters *parameters )
{ 
  TLSPlaintext header;
  unsigned char *send_buffer;
  int send_buffer_size;
  int padding_length = 0;
  unsigned char *mac = NULL;
  digest_ctx digest;
  CipherSuite *active_suite;
  active_suite = &suites[ parameters->suite ];
    
  if ( active_suite->new_digest )
  { 
    // Allocate enough space for the 8-byte sequence number, the 5-byte pseudo
    // header, and the content.
    unsigned char *mac_buffer = malloc( 13 + content_len );
    int sequence_num;
    
    mac = ( unsigned char * ) malloc( active_suite->hash_size );
    active_suite->new_digest( &digest );

    memset( mac_buffer, 0x0, 8 );
    sequence_num = htonl( parameters->seq_num );
    memcpy( mac_buffer + 4, &sequence_num, sizeof( int ) );
    
    // These will be overwritten below
    header.type = content_type;
    header.version.major = 3;
    header.version.minor = 1;
    header.length = htons( content_len );
    mac_buffer[ 8 ] = header.type;
    mac_buffer[ 9 ] = header.version.major;
    mac_buffer[ 10 ] = header.version.minor;
    memcpy( mac_buffer + 11, &header.length, sizeof( short ) );
    
    memcpy( mac_buffer + 13, content, content_len );
    hmac( parameters->MAC_secret,
          active_suite->hash_size,
          mac_buffer, 13 + content_len,
          &digest );

    memcpy( mac, digest.hash, active_suite->hash_size );

    free( mac_buffer );
 }

  send_buffer_size = content_len + active_suite->hash_size;

  if ( active_suite->block_size )
  {
    padding_length = active_suite->block_size - 
      ( send_buffer_size % active_suite->block_size );
    send_buffer_size += padding_length;
  } 
  
  // Add space for the header, but only after computing padding
  send_buffer_size +=5;

  send_buffer = ( unsigned char * ) malloc( send_buffer_size );

  if ( mac )
  {
    memcpy( send_buffer + content_len + 5, mac, active_suite->hash_size + padding_length );
    free( mac );
  } 
  
  if ( padding_length > 0 )
  {
    unsigned char *padding;
    for ( padding = send_buffer + send_buffer_size - 1;
          padding > ( send_buffer + ( send_buffer_size - padding_length - 1 ) );
          padding-- )
    {
      *padding = ( padding_length - 1 );
    }
  }

  header.type = content_type;
  header.version.major = TLS_VERSION_MAJOR;
  header.version.minor = TLS_VERSION_MINOR;
  header.length = htons( content_len + active_suite->hash_size + padding_length );
  send_buffer[ 0 ] = header.type;
  send_buffer[ 1 ] = header.version.major;
  send_buffer[ 2 ] = header.version.minor;
  memcpy( send_buffer + 3, &header.length, sizeof( short ) );
  memcpy( send_buffer + 5, content, content_len );

  if ( active_suite->bulk_encrypt )
  {
    unsigned char *encrypted_buffer = malloc( send_buffer_size );
    // The first 5 bytes (the header) aren't encrypted
    memcpy( encrypted_buffer, send_buffer, 5 );
    active_suite->bulk_encrypt( send_buffer + 5, send_buffer_size - 5, 
      encrypted_buffer + 5, parameters->IV, parameters->key );
    free( send_buffer );
    send_buffer = encrypted_buffer;
  }

  if ( send( connection, ( void * ) send_buffer, 
       send_buffer_size, 0 ) < send_buffer_size )
  {
    return -1;
  }

  parameters->seq_num++;

  free( send_buffer );

  return 0;
}

static int send_alert_message( int connection, 
                               int alert_code,
                               ProtectionParameters *parameters )
{
  char buffer[ 2 ];

  // TODO support warnings
  buffer[ 0 ] = fatal;
  buffer[ 1 ] = alert_code;

  return send_message( connection, content_alert, buffer, 2, parameters );
}

static int send_handshake_message( int connection,
                                   int msg_type,
                                   const unsigned char *message,
                                   int message_len,
                                   TLSParameters *parameters )
{
  Handshake     record;
  short         send_buffer_size;
  unsigned char *send_buffer;
  int           response;

  record.msg_type = msg_type;
  record.length = htons( message_len ) << 8; // To deal with 24-bits...
  send_buffer_size = message_len + 4; // space for the handshake header

  send_buffer = ( unsigned char * ) malloc( send_buffer_size );
  send_buffer[ 0 ] = record.msg_type;
  memcpy( send_buffer + 1, &record.length, 3 );
  memcpy( send_buffer + 4, message, message_len );

  update_digest( &parameters->md5_handshake_digest, send_buffer, 
    send_buffer_size );
  update_digest( &parameters->sha1_handshake_digest, send_buffer, 
    send_buffer_size );

  response = send_message( connection, content_handshake, 
                       send_buffer, send_buffer_size, &parameters->active_send_parameters );

  free( send_buffer );

  return response;
}

/**
 6.3: Compute a key block, including MAC secrets, keys, and IVs for client & server
Notice that the seed is server random followed by client random (whereas for master
secret computation, it's client random followed by server random).  Sheesh!
 */
static void calculate_keys( TLSParameters *parameters )
{
  // XXX assuming send suite & recv suite will always be the same
  CipherSuite *suite = &( suites[ parameters->pending_send_parameters.suite ] );
  const char *label = "key expansion";
  int key_block_length =
    suite->hash_size * 2 +
    suite->key_size * 2 +
    suite->IV_size * 2;
  char seed[ RANDOM_LENGTH * 2 ];
  unsigned char *key_block = ( unsigned char * ) malloc( key_block_length );
  unsigned char *key_block_ptr;
  ProtectionParameters *send_parameters = &parameters->pending_send_parameters;
  ProtectionParameters *recv_parameters = &parameters->pending_recv_parameters;

  memcpy( seed, parameters->server_random, RANDOM_LENGTH );
  memcpy( seed + RANDOM_LENGTH, parameters->client_random, RANDOM_LENGTH );

  PRF( parameters->master_secret, MASTER_SECRET_LENGTH,
    label, strlen( label ),
    seed, RANDOM_LENGTH * 2,
    key_block, key_block_length );

  send_parameters->MAC_secret = ( unsigned char * ) malloc( suite->hash_size );
  recv_parameters->MAC_secret = ( unsigned char * ) malloc( suite->hash_size );
  send_parameters->key = ( unsigned char * ) malloc( suite->key_size );
  recv_parameters->key = ( unsigned char * ) malloc( suite->key_size );
  send_parameters->IV = ( unsigned char * ) malloc( suite->IV_size );
  recv_parameters->IV = ( unsigned char * ) malloc( suite->IV_size );
  
  key_block_ptr = read_buffer( send_parameters->MAC_secret, key_block, 
    suite->hash_size );
  key_block_ptr = read_buffer( recv_parameters->MAC_secret, key_block_ptr, 
    suite->hash_size );
  key_block_ptr = read_buffer( send_parameters->key, key_block_ptr, 
    suite->key_size );
  key_block_ptr = read_buffer( recv_parameters->key, key_block_ptr, 
    suite->key_size );
  key_block_ptr = read_buffer( send_parameters->IV, key_block_ptr, 
    suite->IV_size );
  key_block_ptr = read_buffer( recv_parameters->IV, key_block_ptr, 
    suite->IV_size );

  switch ( suite->id )
  {
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
    case TLS_DH_anon_WITH_RC4_128_MD5:
      {
      rc4_state *read_state = malloc( sizeof( rc4_state ) );
      rc4_state *write_state = malloc( sizeof( rc4_state ) );
      read_state->i = read_state->j = write_state->i = write_state->j = 0;
      send_parameters->IV = ( unsigned char * ) read_state;
      recv_parameters->IV = ( unsigned char * ) write_state;
      memset( read_state->S, '\0', RC4_STATE_ARRAY_LEN );
      memset( write_state->S, '\0', RC4_STATE_ARRAY_LEN );
      }
      break;
    default:
      break;
  }

  free( key_block );
}

/**
 * Turn the premaster secret into an actual master secret (the
 * server side will do this concurrently) as specified in section 8.1:
 * master_secret = PRF( pre_master_secret, "master secret", 
 * ClientHello.random + ServerHello.random );
 * ( premaster_secret, parameters );
 * Note that, with DH, the master secret len is determined by the generator (p)
 * value.
 */
static void compute_master_secret( const unsigned char *premaster_secret,
                                   int premaster_secret_len,
                                   TLSParameters *parameters )
{
  const char *label = "master secret";
  PRF( premaster_secret, premaster_secret_len,
       label, strlen( label ),
       // Note - cheating, since client_random & server_random are defined
       // sequentially in the structure
       parameters->client_random, RANDOM_LENGTH * 2,
       parameters->master_secret, MASTER_SECRET_LENGTH );
}

/**
 * Build and submit a TLS client hello handshake on the active
 * connection.  It is up to the caller of this function to wait
 * for the server reply.
 */
static int send_client_hello( int connection, TLSParameters *parameters )
{
  ClientHello       package;
  unsigned short    supported_suites[ 1 ];
  unsigned char     supported_compression_methods[ 1 ];
  int               send_buffer_size;
  char              *send_buffer;
  void              *write_buffer;
  time_t            local_time;
  int               status = 1;

  package.client_version.major = TLS_VERSION_MAJOR;
  package.client_version.minor = TLS_VERSION_MINOR;
  time( &local_time );
  package.random.gmt_unix_time = htonl( local_time );
  // TODO - actually make this random.
  // This is 28 bytes, but client random is 32 - the first four bytes of
  // "client random" are the GMT unix time computed above.
  memcpy( parameters->client_random, &package.random.gmt_unix_time, 4 );
  memcpy( package.random.random_bytes, parameters->client_random + 4, 28 );
  package.session_id_length = 0;
  package.session_id = NULL;
  // note that this is bytes, not count.
  package.cipher_suites_length = htons( 2 );
  supported_suites[ 0 ] = htons( TLS_RSA_WITH_3DES_EDE_CBC_SHA );
  package.cipher_suites = supported_suites;
  package.compression_methods_length = 1;
  supported_compression_methods[ 0 ] = 0;
  package.compression_methods = supported_compression_methods;

  // Compute the size of the ClientHello message after flattening.
  send_buffer_size = sizeof( ProtocolVersion ) + 
     sizeof( Random ) + 
     sizeof( unsigned char ) +
     ( sizeof( unsigned char ) * package.session_id_length ) +
     sizeof( unsigned short ) +
     ( sizeof( unsigned short ) * 1 ) +
     sizeof( unsigned char ) +
     sizeof( unsigned char );

  write_buffer = send_buffer = ( char * ) malloc( send_buffer_size );
  
  write_buffer = append_buffer( write_buffer, ( void * ) 
     &package.client_version.major, 1 );
  write_buffer = append_buffer( write_buffer, ( void * ) 
     &package.client_version.minor, 1 );
  write_buffer = append_buffer( write_buffer, ( void * )     
     &package.random.gmt_unix_time, 4 );
  write_buffer = append_buffer( write_buffer, ( void * ) 
     &package.random.random_bytes, 28 );
  write_buffer = append_buffer( write_buffer, ( void * )  
     &package.session_id_length, 1 );
  if ( package.session_id_length > 0 )
  {
    write_buffer = append_buffer( write_buffer, 
      ( void * )package.session_id,
      package.session_id_length );
  }
  write_buffer = append_buffer( write_buffer, 
     ( void * ) &package.cipher_suites_length, 2 );
  write_buffer = append_buffer( write_buffer, 
    ( void * ) package.cipher_suites, 2 );
  write_buffer = append_buffer( write_buffer, 
    ( void * ) &package.compression_methods_length, 1 );
  if ( package.compression_methods_length > 0 )
  {
    write_buffer = append_buffer( write_buffer, 
       ( void * ) package.compression_methods, 1 );
  }

  assert( ( ( char * ) write_buffer - send_buffer ) == send_buffer_size );

  status = send_handshake_message( connection, client_hello, send_buffer, 
     send_buffer_size, parameters );

  free( send_buffer );

  return status;
}

static char *parse_server_hello( char *read_pos, 
                                 int pdu_length, 
                                 TLSParameters *parameters )
{
  ServerHello hello;
  
  read_pos = read_buffer( ( void * ) &hello.server_version.major,
    ( void * ) read_pos, 1 );
  read_pos = read_buffer( ( void * ) &hello.server_version.minor,
    ( void * ) read_pos, 1 );
  read_pos = read_buffer( ( void * ) &hello.random.gmt_unix_time,
    ( void * ) read_pos, 4 );
  // *DON'T* put this in host order, since it's not used as a time!  Just
  // accept it as is
  read_pos = read_buffer( ( void * ) hello.random.random_bytes, 
    ( void * ) read_pos, 28 );
  read_pos = read_buffer( ( void * ) &hello.session_id_length, 
     ( void * ) read_pos, 1 );
  read_pos = read_buffer( ( void * ) hello.session_id, 
     ( void * ) read_pos, hello.session_id_length );
  read_pos = read_buffer( ( void * ) &hello.cipher_suite, 
     ( void * ) read_pos, 2 );
  hello.cipher_suite = ntohs( hello.cipher_suite );

  // TODO check that these values were actually in the client hello
  // list.  
  parameters->pending_recv_parameters.suite = hello.cipher_suite;
  parameters->pending_send_parameters.suite = hello.cipher_suite;
  
  read_pos = read_buffer( ( void * ) &hello.compression_method, 
     ( void * ) read_pos, 1 );
  if ( hello.compression_method != 0 )
  {
    fprintf( stderr, "Error, server wants compression.\n" );
    return NULL;
  }

  // TODO - abort if there's more data here than in the spec (per section 7.4.1.2,
  // forward compatibility note)
  // TODO - abort if version < 3.1 with "protocol_version" alert error

  // 28 random bytes, but the preceding four bytes are the reported GMT unix time
  memcpy( ( void * ) parameters->server_random, &hello.random.gmt_unix_time, 4 );
  memcpy( ( void * ) ( parameters->server_random + 4 ), 
     ( void * ) hello.random.random_bytes, 28 );
  return read_pos;
}

int rsa_key_exchange( rsa_key *public_key,
                      unsigned char *premaster_secret,
                      unsigned char **key_exchange_message )
{
  int i;
  unsigned char *encrypted_premaster_secret = NULL;
  int encrypted_length;

  // first two bytes are protocol version
  premaster_secret[ 0 ] = TLS_VERSION_MAJOR;
  premaster_secret[ 1 ] = TLS_VERSION_MINOR;
  for ( i = 2; i < MASTER_SECRET_LENGTH; i++ )
  {
    // XXX SHOULD BE RANDOM!
    premaster_secret[ i ] = i;
  }

  encrypted_length = rsa_encrypt( premaster_secret, MASTER_SECRET_LENGTH,
    &encrypted_premaster_secret, public_key );

  *key_exchange_message = ( unsigned char * ) malloc( encrypted_length + 2 );
  (*key_exchange_message)[ 0 ] = 0;
  (*key_exchange_message)[ 1 ] = encrypted_length;
  memcpy( (*key_exchange_message) + 2, encrypted_premaster_secret, 
    encrypted_length );

  free( encrypted_premaster_secret );
  
  return encrypted_length + 2;
}

/**
 * Just compute Yc = g^a % p and return it in "key_exchange_message".  The 
 * premaster secret is Ys ^ a % p.
 */
int dh_key_exchange( dh_key *server_dh_key,
                     unsigned char *premaster_secret,
                     unsigned char **key_exchange_message )
{
  huge Yc;
  huge Z;
  huge a;
  int message_size;
  short transmit_len;

  // TODO obviously, make this random, and much longer
  set_huge( &a, 6 );
  mod_pow( &server_dh_key->g, &a, &server_dh_key->p, &Yc );
  mod_pow( &server_dh_key->Y, &a, &server_dh_key->p, &Z );

  // Now copy Z into premaster secret and Yc into key_exchange_message
  memcpy( premaster_secret, Z.rep, Z.size );
  message_size = Yc.size + 2;
  transmit_len = htons( Yc.size );
  *key_exchange_message = malloc( message_size );
  memcpy( *key_exchange_message, &transmit_len, 2 );
  memcpy( *key_exchange_message + 2, Yc.rep, Yc.size );

  free_huge( &Yc );
  free_huge( &Z );
  free_huge( &a );

  return message_size;
}

/**
 * Send the client key exchange message, as detailed in section 7.4.7
 * Use the server's public key (if it has one) to encrypt a key. (or DH?)
 * Return true if this succeeded, false otherwise.
 */ 
static int send_client_key_exchange( int connection, TLSParameters *parameters )
{   
  unsigned char *key_exchange_message;
  int key_exchange_message_len;
  unsigned char *premaster_secret;
  int premaster_secret_len;

  switch ( parameters->pending_send_parameters.suite ) {
    case TLS_NULL_WITH_NULL_NULL:
      // XXX this is an error, exit here
      break;
    case TLS_RSA_WITH_NULL_MD5:
    case TLS_RSA_WITH_NULL_SHA:
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
    case TLS_RSA_WITH_IDEA_CBC_SHA:
    case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_RSA_WITH_DES_CBC_SHA:
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA:
      premaster_secret_len = MASTER_SECRET_LENGTH;
      premaster_secret = malloc( premaster_secret_len );
      key_exchange_message_len = rsa_key_exchange( 
        &parameters->server_public_key.rsa_public_key,
        premaster_secret, &key_exchange_message );
      break;
    case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_DSS_WITH_DES_CBC_SHA:
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_RSA_WITH_DES_CBC_SHA:
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_DSS_WITH_DES_CBC_SHA:
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_RSA_WITH_DES_CBC_SHA:
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
    case TLS_DH_anon_WITH_RC4_128_MD5:
    case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_anon_WITH_DES_CBC_SHA:
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
      premaster_secret_len = parameters->server_dh_key.p.size;
      premaster_secret = malloc( premaster_secret_len );
      key_exchange_message_len = dh_key_exchange( &parameters->server_dh_key,
        premaster_secret, &key_exchange_message );
      break;
    default:
      return 0;
  }

  if ( send_handshake_message( connection, client_key_exchange,
       key_exchange_message, key_exchange_message_len, parameters ) )
  {
    free( key_exchange_message );
    return 0;
  }

  free( key_exchange_message );

  // Now, turn the premaster secret into an actual master secret (the
  // server side will do this concurrently).
  compute_master_secret( premaster_secret, premaster_secret_len, parameters );

  // XXX - for security, should also "purge" the premaster secret from
  // memory.
  calculate_keys( parameters );

  free( premaster_secret );

  return 1;
}

void compute_handshake_hash( TLSParameters *parameters, unsigned char *handshake_hash )
{
  digest_ctx tmp_md5_handshake_digest;
  digest_ctx tmp_sha1_handshake_digest;

  // "cheating".  Copy the handshake digests into local memory (and change
  // the hash pointer) so that we can finalize twice (again in "recv")
  memcpy( &tmp_md5_handshake_digest, &parameters->md5_handshake_digest, 
    sizeof( digest_ctx ) );
  memcpy( &tmp_sha1_handshake_digest, &parameters->sha1_handshake_digest, 
    sizeof( digest_ctx ) );

  tmp_md5_handshake_digest.hash = ( unsigned int * ) malloc( MD5_BYTE_SIZE );
  tmp_sha1_handshake_digest.hash = ( unsigned int * ) malloc( SHA1_BYTE_SIZE );
  memcpy( tmp_md5_handshake_digest.hash, parameters->md5_handshake_digest.hash, 
    MD5_BYTE_SIZE );
  memcpy( tmp_sha1_handshake_digest.hash, parameters->sha1_handshake_digest.hash, 
    SHA1_BYTE_SIZE );

  finalize_digest( &tmp_md5_handshake_digest );
  finalize_digest( &tmp_sha1_handshake_digest );

  memcpy( handshake_hash, tmp_md5_handshake_digest.hash, MD5_BYTE_SIZE );
  memcpy( handshake_hash + MD5_BYTE_SIZE, tmp_sha1_handshake_digest.hash, 
    SHA1_BYTE_SIZE );

  free( tmp_md5_handshake_digest.hash );
  free( tmp_sha1_handshake_digest.hash );
}

/**
 * 7.4.9:
 * verify_data = PRF( master_secret, "client finished", MD5(handshake_messages) +
 *  SHA-1(handshake_messages)) [0..11]
 *
 * master_secret = PRF( pre_master_secret, "master secret", ClientHello.random +
 *  ServerHello.random );
 * always 48 bytes in length.
 */
#define VERIFY_DATA_LEN 12

static void compute_verify_data( const char *finished_label,
                                 TLSParameters *parameters,
                                 char *verify_data )
{
  unsigned char handshake_hash[ ( MD5_RESULT_SIZE * sizeof( int ) ) +
                             ( SHA1_RESULT_SIZE * sizeof( int ) ) ];

  compute_handshake_hash( parameters, handshake_hash );

  PRF( parameters->master_secret, MASTER_SECRET_LENGTH,
       finished_label, strlen( finished_label ),
       handshake_hash,
       MD5_RESULT_SIZE * sizeof( int ) + SHA1_RESULT_SIZE * sizeof( int ),
       verify_data, VERIFY_DATA_LEN );
}

static int send_change_cipher_spec( int connection, TLSParameters *parameters )
{ 
  char          send_buffer[ 1 ];
  send_buffer[ 0 ] = 1;
  send_message( connection, content_change_cipher_spec, send_buffer, 1, 
    &parameters->active_send_parameters );

  parameters->pending_send_parameters.seq_num = 0;

  memcpy( &parameters->active_send_parameters,
          &parameters->pending_send_parameters,
          sizeof( ProtectionParameters ) );

  init_protection_parameters( &parameters->pending_send_parameters );

  return 1;
}

static int send_finished( int connection, 
                          TLSParameters *parameters )
{
  unsigned char verify_data[ VERIFY_DATA_LEN ];
  
  compute_verify_data( "client finished", parameters, verify_data );
  send_handshake_message( connection, finished, verify_data, VERIFY_DATA_LEN,
    parameters );

  return 1;
}

static unsigned char *parse_finished( unsigned char *read_pos,
                                      int pdu_length,
                                      TLSParameters *parameters )
{
  unsigned char verify_data[ VERIFY_DATA_LEN ];

  parameters->server_finished = 1;

  compute_verify_data( "server finished", parameters, verify_data );

  if ( memcmp( read_pos, verify_data, VERIFY_DATA_LEN ) )
  {
    return NULL;
  }

  return read_pos + pdu_length;
}

static void report_alert( Alert *alert )
{
  printf( "Alert - " );
  
  switch ( alert->level )
  {
    case warning:
      printf( "Warning: " );
      break;
    case fatal:
      printf( "Fatal: " );
      break;
    default:
      printf( "UNKNOWN ALERT TYPE %d (!!!): ", alert->level );
      break;
  }

  switch ( alert->description )
  {
    case close_notify:
      printf( "Close notify\n" );
      break;
    case unexpected_message:
      printf( "Unexpected message\n" );
      break;
    case bad_record_mac:
      printf( "Bad Record Mac\n" );
      break;
    case decryption_failed:
      printf( "Decryption Failed\n" );
      break;
    case record_overflow:
      printf( "Record Overflow\n" );
      break;
    case decompression_failure:
      printf( "Decompression Failure\n" );
      break;
    case handshake_failure:
      printf( "Handshake Failure\n" );
      break;
    case bad_certificate:
      printf( "Bad Certificate\n" );
      break;
    case unsupported_certificate:
      printf( "Unsupported Certificate\n" );
      break;
    case certificate_revoked:
      printf( "Certificate Revoked\n" );
      break;
    case certificate_expired:
      printf( "Certificate Expired\n" );
      break;
    case certificate_unknown:
      printf( "Certificate Unknown\n" );
      break;
    case illegal_parameter:
      printf( "Illegal Parameter\n" );
      break;
    case unknown_ca:
      printf( "Unknown CA\n" );
      break;
    case access_denied:
      printf( "Access Denied\n" );
      break;
    case decode_error:
      printf( "Decode Error\n" );
      break;
    case decrypt_error:
      printf( "Decrypt Error\n" );
      break;
    case export_restriction:
      printf( "Export Restriction\n" );
      break;
    case protocol_version:
      printf( "Protocol Version\n" );
      break;
    case insufficient_security:
      printf( "Insufficient Security\n" );
      break;
    case internal_error:
      printf( "Internal Error\n" );
      break;
    case user_canceled:
      printf( "User canceled\n" );
      break;
    case no_renegotiation:
      printf( "No renegotiation\n" );
      break;
    default:
      printf( "UNKNOWN ALERT DESCRIPTION %d (!!!)\n", alert->description );
      break;
  }
}

/** 
 * Decrypt a message and verify its MAC according to the active cipher spec
 * (as given by "parameters").  Free the space allocated by encrypted message
 * and allocate new space for the decrypted message (if decrypting is "identity", 
 * then decrypted will point to encrypted).  The caller must always issue a
 * "free decrypted_message".
 * Return the length of the message, or -1 if the MAC doesn't verify.  The return 
 * value will almost always be different than "encrypted_length", since it strips 
 * off the MAC if present as well as bulk cipher padding (if a block cipher 
 * algorithm is being used).
 */ 
static int tls_decrypt( const unsigned char *header, // needed for MAC verification
                        unsigned char *encrypted_message,
                        short encrypted_length,
                        unsigned char **decrypted_message, 
                        ProtectionParameters *parameters )
{ 
  short decrypted_length;
  digest_ctx digest;
  unsigned char *mac_buffer;
  int sequence_number;
  short length;
  CipherSuite *active_suite = &( suites[ parameters->suite ] );
  
  *decrypted_message = ( unsigned char * ) malloc( encrypted_length );
  
  if ( active_suite->bulk_decrypt )
  {
    active_suite->bulk_decrypt( encrypted_message, encrypted_length, 
      *decrypted_message, parameters->IV, parameters->key );
    decrypted_length = encrypted_length;
    // Strip off padding
    if ( active_suite->block_size )
    {
      decrypted_length -= ( (*decrypted_message)[ encrypted_length - 1 ] + 1 );
    }
  }
  else
  {
    // Do nothing, no bulk cipher algorithm chosen.
    // Still have to memcpy so that "free" in caller is consistent
    decrypted_length = encrypted_length;
    memcpy( *decrypted_message, encrypted_message, encrypted_length );
  }

  // Now, verify the MAC (if the active cipher suite includes one)
  if ( active_suite->new_digest )
  {
    active_suite->new_digest( &digest );

    decrypted_length -= ( digest.hash_len * sizeof( int ) );

    // Allocate enough space for the 8-byte sequence number, the TLSPlainText 
    // header, and the fragment (e.g. the decrypted message).
    mac_buffer = malloc( 13 + decrypted_length );
    memset( mac_buffer, 0x0, 13 + decrypted_length );
    sequence_number = htonl( parameters->seq_num );
    memcpy( mac_buffer + 4, &sequence_number, sizeof( int ) );
   
    // Copy first three bytes of header; last two bytes reflected the
    // message length, with MAC attached.  Since the MAC was computed
    // by the other side before it was attached (obviously), that MAC
    // was computed using the original length.
    memcpy( mac_buffer + 8, header, 3 );
    length = htons( decrypted_length );
    memcpy( mac_buffer + 11, &length, 2 );
    memcpy( mac_buffer + 13, *decrypted_message, decrypted_length );

    hmac( parameters->MAC_secret, digest.hash_len * sizeof( int ),
      mac_buffer, decrypted_length + 13, &digest );

    if ( memcmp( digest.hash,
                 (*decrypted_message) + decrypted_length,
                 digest.hash_len * sizeof( int ) ) )
    {
      return -1;
    }

    free( mac_buffer );
  }

  return decrypted_length;
}

/**
 * Read a TLS packet off of the connection (assuming there's one waiting) and try
 * to update the security parameters based on the type of message received.  If
 * the read times out, or if an alert is received, return an error code; return 0
 * on success.
 * TODO - assert that the message received is of the type expected (for example,
 * if a server hello is expected but not received, this is a fatal error per 
 * section 7.3).  returns -1 if an error occurred (this routine will have sent an
 * appropriate alert). Otherwise, return the number of bytes read if the packet 
 * includes application data; 0 if the packet was a handshake.  -1 also indicates 
 * that an alert was received.
 */
static int receive_tls_msg( int connection,
                            char *buffer,
                            int bufsz,	
                            TLSParameters *parameters )
{
  TLSPlaintext  message;
  unsigned char *read_pos, *msg_buf, *decrypted_message, *encrypted_message;
  unsigned char header[ 5 ];  // size of TLSPlaintext
  int bytes_read, accum_bytes;
  int decrypted_length;

  // STEP 1 - read off the TLS Record layer
  // First, check to see if there's any data left over from a previous read.
  // If there is, pass that back up.
  // This means that if the caller isn't quick about reading available data,
  // TLS alerts can be missed.
  if ( parameters->unread_buffer != NULL )
  {
    decrypted_message = parameters->unread_buffer;
    decrypted_length = parameters->unread_length;
    parameters->unread_buffer = NULL;
    parameters->unread_length = 0;

    message.type = content_application_data;
  }
  else
  {
    if ( recv( connection, header, 5, 0 ) <= 0 )
    {
      // No data available; it's up to the caller whether this is an error or not.
      return -1;
    }
    
    message.type = header[ 0 ];
    message.version.major = header[ 1 ];
    message.version.minor = header[ 2 ];
    memcpy( &message.length, header + 3, 2 );
    message.length = htons( message.length );
    encrypted_message = ( char * ) malloc( message.length );

    // keep looping & appending until all bytes are accounted for
    accum_bytes = 0;
    msg_buf = encrypted_message;
    while ( accum_bytes < message.length )
    {
      if ( ( bytes_read = recv( connection, ( void * ) msg_buf, 
             message.length - accum_bytes, 0 ) ) <= 0 )
      {
        int status;
        perror( "While reading a TLS packet" );

        if ( ( status = send_alert_message( connection, 
               illegal_parameter, &parameters->active_send_parameters ) ) )
        {
          free( msg_buf );
          return status;
        }
        return -1;
      }
      accum_bytes += bytes_read;
      msg_buf += bytes_read;
    }
    // If a cipherspec is active, all of "encrypted_message" will be encrypted.  
    // Must decrypt it before continuing.  This will change the message length 
    // in all cases, since decrypting also involves verifying a MAC (unless the 
    // active cipher spec is NULL_WITH_NULL_NULL).
    decrypted_message = NULL;
    decrypted_length = tls_decrypt( header, encrypted_message, message.length,
      &decrypted_message, &parameters->active_recv_parameters );

    free( encrypted_message );

    if ( decrypted_length < 0 )
    {
      send_alert_message( connection, bad_record_mac, 
        &parameters->active_send_parameters );
      return -1;
    }
    parameters->active_recv_parameters.seq_num++;
  }

  read_pos = decrypted_message;
 
  if ( message.type == content_handshake )
  {
    while ( ( read_pos - decrypted_message ) < decrypted_length )
    {
      Handshake handshake;
      const unsigned char *handshake_msg_start = read_pos;

      // Now, read the handshake type and length of the next packet
      // TODO - this fails if the read, above, only got part of the message
      read_pos = read_buffer( ( void * ) &handshake.msg_type, 
               ( void * ) read_pos, 1 );
      handshake.length = read_pos[ 0 ] << 16 | read_pos[ 1 ] << 8 | read_pos[ 2 ];

      read_pos += 3;

      // TODO check for negative or unreasonably long length
      // Now, depending on the type, read in and process the packet itself.
      switch ( handshake.msg_type )
      {
        // Client-side messages
        case server_hello:
          read_pos = parse_server_hello( read_pos, handshake.length, 
             parameters );
          if ( read_pos == NULL )  /* error occurred */
          {
            free( msg_buf );
            send_alert_message( connection, illegal_parameter, &parameters->active_send_parameters );
            return -1;
          }
          break;
        case certificate:
          read_pos = parse_x509_chain( read_pos, handshake.length,
            &parameters->server_public_key );
          if ( read_pos == NULL )
          {
            printf( "Rejected, bad certificate\n" );
            send_alert_message( connection, bad_certificate, &parameters->active_send_parameters );
            return -1;
          }
          break;
        case server_hello_done:
          parameters->server_hello_done = 1;
          break;
        case finished:
          {
            read_pos = parse_finished( read_pos, handshake.length, parameters );
            if ( read_pos == NULL )
            {
              send_alert_message( connection, illegal_parameter, &parameters->active_send_parameters );
              return -1;
            }
          }
          break;
        default:
          printf( "Ignoring unrecognized handshake message %d\n", 
             handshake.msg_type );
          // Silently ignore any unrecognized types per section 6
          // TODO However, out-of-order messages should result in a fatal alert
          // per section 7.4
          read_pos += handshake.length;
          break;
      }

      update_digest( &parameters->md5_handshake_digest, handshake_msg_start, 
        handshake.length + 4 );
      update_digest( &parameters->sha1_handshake_digest, handshake_msg_start, 
        handshake.length + 4 );
    }
  }
  else if ( message.type == content_alert )
  {
    while ( ( read_pos - decrypted_message ) < decrypted_length )
    {
      Alert alert;

      read_pos = read_buffer( ( void * ) &alert.level, 
         ( void * ) read_pos, 1 );
      read_pos = read_buffer( ( void * ) &alert.description, 
         ( void * ) read_pos, 1 );

      report_alert( &alert );

      if ( alert.level == fatal )
      {
        return -1;
      }
    }
  }
  else if ( message.type == content_change_cipher_spec )
  { 
    while ( ( read_pos - decrypted_message ) < decrypted_length )
    {
      unsigned char change_cipher_spec_type;
    
      read_pos = read_buffer( ( void * ) &change_cipher_spec_type, 
        ( void * ) read_pos, 1 );

      if ( change_cipher_spec_type != 1 )
      {
        printf( "Error - received message ChangeCipherSpec, but type != 1\n" );
        exit( 0 );
      }
      else
      {
        parameters->pending_recv_parameters.seq_num = 0;
        memcpy( &parameters->active_recv_parameters,
                &parameters->pending_recv_parameters,
                sizeof( ProtectionParameters ) );
        init_protection_parameters( &parameters->pending_recv_parameters );
      }
    }
  }
  else if ( message.type == content_application_data )
  {
    if ( decrypted_length <= bufsz )
    {
      memcpy( buffer, decrypted_message, decrypted_length );
    }
    else
    {
      // Need to hang on to a buffer of data here and pass it back for the
      // next call
      memcpy( buffer, decrypted_message, bufsz );
      parameters->unread_length = decrypted_length - bufsz;
      parameters->unread_buffer = malloc( parameters->unread_length );
      memcpy( parameters->unread_buffer, decrypted_message + bufsz, 
        parameters->unread_length );

      decrypted_length = bufsz;
    }
  }
  else
  {
    // Ignore content types not understood, per section 6 of the RFC.
    printf( "Ignoring non-recognized content type %d\n", message.type );
  }

  free( decrypted_message );
    
  return decrypted_length;
}


/**
 * Negotiate TLS parameters on an already-established socket.
 */
int tls_connect( int connection,
                 TLSParameters *parameters )
{
  init_parameters( parameters );
  new_md5_digest( &parameters->md5_handshake_digest );
  new_sha1_digest( &parameters->sha1_handshake_digest );

  // Step 1. Send the TLS handshake "client hello" message
  if ( send_client_hello( connection, parameters ) < 0 )
  {
    perror( "Unable to send client hello" );
    return 1;
  }

  // Step 2. Receive the server hello response
  parameters->server_hello_done = 0;
  while ( !parameters->server_hello_done )
  {
    if ( receive_tls_msg( connection, NULL, 0, parameters ) < 0 )
    {
      perror( "Unable to receive server hello" );
      return 2;
    }
  }
  // Step 3. Send client key exchange, change cipher spec (7.1) and encrypted 
  // handshake message
  if ( !( send_client_key_exchange( connection, parameters ) ) )
  {
    perror( "Unable to send client key exchange" );
    return 3;
  }

  if ( !( send_change_cipher_spec( connection, parameters ) ) )
  {
    perror( "Unable to send client change cipher spec" );
    return 4;
  }

  // This message will be encrypted using the newly negotiated keys
  if ( !( send_finished( connection, parameters ) ) )
  {
    perror( "Unable to send client finished" );
    return 5;
  }

  parameters->server_finished = 0;
  while ( !parameters->server_finished )
  {
    if ( receive_tls_msg( connection, NULL, 0, parameters ) < 0 )
    {
      perror( "Unable to receive server finished" );
      return 6;
    }
  }

  return 0;
}

int tls_send( int connection,
              const char *application_data,
              int length,
              int options,
              TLSParameters *parameters )
{
  send_message( connection, content_application_data, application_data, length,
    &parameters->active_send_parameters );
  return length;
}

int tls_recv( int connection, char *target_buffer, int buffer_size, int options,
              TLSParameters *parameters )
{
  int bytes_decrypted = 0;

  bytes_decrypted = receive_tls_msg( connection, target_buffer, buffer_size, 
    parameters );

  return bytes_decrypted;
}

static void free_protection_parameters( ProtectionParameters *parameters )
{
  if ( parameters->MAC_secret )
  {
    free( parameters->MAC_secret );
  }
  if ( parameters->key )
  {
    free( parameters->key );
  }
  if ( parameters->IV )
  {
    free( parameters->IV );
  }
}

int tls_shutdown( int connection, TLSParameters *parameters )
{ 
  send_alert_message( connection, close_notify, 
    &parameters->active_send_parameters );
  if ( parameters->unread_buffer )
  {
    free( parameters->unread_buffer );
  }
  free_protection_parameters( &parameters->pending_send_parameters );
  free_protection_parameters( &parameters->pending_recv_parameters );
  free_protection_parameters( &parameters->active_send_parameters );
  free_protection_parameters( &parameters->active_recv_parameters );

  return 1;
}
