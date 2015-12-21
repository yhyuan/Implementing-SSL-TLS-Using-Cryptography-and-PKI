#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "ssl.h"
#include "md5.h"
#include "des.h"
#include "rc4.h"

#define NUM_CIPHER_SPECS  3
static CipherSpec specs[] =
{
  { SSL_CK_DES_64_CBC_WITH_MD5, 8, 8, 8, MD5_BYTE_SIZE, des_encrypt, 
    des_decrypt, new_md5_digest },
  { SSL_CK_DES_192_EDE3_CBC_WITH_MD5, 8, 8, 24, MD5_BYTE_SIZE, 
    des3_encrypt, des3_decrypt, new_md5_digest },  
  { SSL_CK_RC4_128_WITH_MD5, 0, 0, 16, MD5_BYTE_SIZE, rc4_128_encrypt, 
    rc4_128_decrypt, new_md5_digest }
};

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

static void init_parameters( SSLParameters *parameters ) 
{ 
  int i; 
  parameters->active_cipher_spec = NULL; 
  parameters->proposed_cipher_spec = NULL; 
  parameters->write_key = NULL; 
  parameters->read_key = NULL; 
  parameters->read_state = NULL;
  parameters->write_state = NULL;
  parameters->write_iv = NULL; 
  parameters->read_iv = NULL; 
  parameters->write_sequence_number = 0; 
  parameters->read_sequence_number = 0; 

  parameters->got_server_hello = 0; 
  parameters->got_server_verify = 0; 
  parameters->handshake_finished = 0; 

  for ( i = 0; i < CHALLENGE_LEN; i++ ) 
  { 
    // XXX this should be random 
    parameters->challenge[ i ] = i; 
  } 

  parameters->master_key = NULL; 

  parameters->server_public_key.modulus = malloc( sizeof( huge ) ); 
  parameters->server_public_key.exponent = malloc( sizeof( huge ) ); 
  set_huge( parameters->server_public_key.modulus, 0 ); 
  set_huge( parameters->server_public_key.exponent, 0 ); 

  parameters->unread_buffer = NULL; 
  parameters->unread_length = 0; 
}

static void add_mac( unsigned char *target, 
                    const unsigned char *src, 
                    int src_len, 
                    SSLParameters *parameters ) 
{ 
  digest_ctx ctx; 
  int sequence_number; 

  parameters->active_cipher_spec->new_digest( &ctx ); 
  update_digest( &ctx, parameters->write_key, 
    parameters->active_cipher_spec->key_size ); 
  update_digest( &ctx, src, src_len ); 
  sequence_number = htonl( parameters->write_sequence_number ); 
  update_digest( &ctx, ( unsigned char * ) &sequence_number, 
    sizeof( int ) ); 
  finalize_digest( &ctx ); 
  
  memcpy( target, ctx.hash, 
    parameters->active_cipher_spec->hash_size ); 
}

static int send_message( int connection, 
                         const unsigned char *data, 
                         unsigned short data_len, 
                         SSLParameters *parameters ) 
{   
  unsigned char *buffer; 
  int buf_len; 
  unsigned short header_len; 

  if ( parameters->active_cipher_spec == NULL ) 
  { 
    buf_len = data_len + 2; 
    buffer = malloc( buf_len ); 
    header_len = htons( data_len ); 
    memcpy( buffer, &header_len, 2 ); 
    buffer[ 0 ] |= 0x80;  // indicate two-byte length 
    memcpy( buffer + 2, data, data_len ); 
  } 
  else 
  { 
    int padding = 0; 
    unsigned char *encrypted, *encrypt_buf, *mac_buf; 

    if ( parameters->active_cipher_spec->block_size ) 
    { 
      padding = parameters->active_cipher_spec->block_size - 
        ( data_len % parameters->active_cipher_spec->block_size ); 
    } 

    buf_len = 3 + // sizeof header 
              parameters->active_cipher_spec->hash_size + // sizeof mac 
              data_len + // sizeof data 
              padding; // sizeof padding 
    buffer = malloc( buf_len ); 
    header_len = htons( buf_len - 3 ); 
    memcpy( buffer, &header_len, 2 ); 
    buffer[ 2 ] = padding; 
    encrypt_buf = malloc( buf_len - 3 ); 
    encrypted = malloc( buf_len - 3 ); 
    memset( encrypt_buf, '\0', buf_len - 3 ); 

    // Insert a MAC at the start of "encrypt_buf" 
    mac_buf = malloc( data_len + padding ); 
    memset( mac_buf, '\0', data_len + padding ); 
    memcpy( mac_buf, data, data_len ); 
    add_mac( encrypt_buf, mac_buf, data_len + padding, parameters ); 
    free( mac_buf ); 

    // Add the data (padding was already set to zeros) 
    memcpy( encrypt_buf + parameters->active_cipher_spec->hash_size, 
      data, data_len ); 

    // Finally encrypt the whole thing 
    parameters->active_cipher_spec->bulk_encrypt( encrypt_buf, 
      buf_len - 3, encrypted, 
      parameters->write_state ? parameters->write_state : 
                                parameters->write_iv,
      parameters->write_key ); 

    memcpy( buffer + 3, encrypted, buf_len - 3 ); 

    free( encrypt_buf ); 
    free( encrypted ); 
  }

  if ( send( connection, ( void * ) buffer, buf_len, 0 ) < buf_len ) 
  { 
    return -1; 
  } 

  parameters->write_sequence_number++; 

  free( buffer ); 

  return 0;
}

static int send_handshake_message( int connection, 
                                   unsigned char message_type, 
                                   unsigned char *data, 
                                   int data_len, 
                                   SSLParameters *parameters ) 
{ 
  unsigned char *buffer; 
  int buf_len; 

  buf_len = data_len + 1; 

  buffer = malloc( buf_len ); 
  buffer[ 0 ] = message_type; 
  memcpy( buffer + 1, data, data_len ); 

  if ( send_message( connection, buffer, buf_len, parameters ) == -1 ) 
  { 
    return -1; 
  } 
  
  free( buffer ); 

  return 0; 
}

static int send_error( int connection, 
                       unsigned short error_code, 
                       SSLParameters *parameters ) 
{ 
  unsigned char buffer[ 3 ]; 
  unsigned short send_error; 

  buffer[ 0 ] = SSL_MT_ERROR; 
  send_error = htons( error_code ); 
  memcpy( buffer + 1, &send_error, sizeof( unsigned short ) ); 

  if ( send_message( connection, buffer, 3, parameters ) == -1 ) 
  { 
    return -1; 
  } 

  return 0; 
}

#define SSL_MT_CLIENT_HELLO             1 

static int send_client_hello( int connection, 
                              SSLParameters *parameters ) 
{ 
  unsigned char *send_buffer, *write_buffer; 
  int buf_len; 
  int i; 
  unsigned short network_number; 
  int status = 0; 
  ClientHello package; 

  package.version_major = 0; 
  package.version_minor = 2; 
  package.cipher_specs_length = sizeof( specs ) / sizeof( CipherSpec ); 
  package.session_id_length = 0; 
  package.challenge_length = CHALLENGE_LEN; 

  // Each cipher spec takes up 3 bytes in SSLv2 
  package.cipher_specs = malloc( sizeof( unsigned char ) * 3 *
    package.cipher_specs_length ); 
  package.session_id = malloc( sizeof( unsigned char ) * 
    package.session_id_length ); 
  package.challenge = malloc( sizeof( unsigned char ) *
    package.challenge_length ); 

  buf_len = sizeof( unsigned char ) * 2 + 
    sizeof( unsigned short ) * 3 + 
    ( package.cipher_specs_length * 3 ) + 
    package.session_id_length + 
    package.challenge_length; 
    
  for ( i = 0; i < package.cipher_specs_length; i++ ) 
  { 
    memcpy( package.cipher_specs + ( i * 3 ), 
      &specs[ i ].cipher_spec_code, 3 ); 
  } 
  memcpy( package.challenge, parameters->challenge, CHALLENGE_LEN ); 

  write_buffer = send_buffer = malloc( buf_len ); 
  
  write_buffer = append_buffer( write_buffer, 
    &package.version_major, 1 ); 
  write_buffer = append_buffer( write_buffer, 
    &package.version_minor, 1 ); 
  network_number = htons( package.cipher_specs_length * 3 ); 
  write_buffer = append_buffer( write_buffer, 
    ( void * ) &network_number, 2 ); 
  network_number = htons( package.session_id_length ); 
  write_buffer = append_buffer( write_buffer, 
    ( void * ) &network_number, 2 ); 
  network_number = htons( package.challenge_length ); 
  write_buffer = append_buffer( write_buffer, 
    ( void * ) &network_number, 2 ); 
  write_buffer = append_buffer( write_buffer, package.cipher_specs, 
    package.cipher_specs_length * 3 ); 
  write_buffer = append_buffer( write_buffer, package.session_id, 
    package.session_id_length ); 
  write_buffer = append_buffer( write_buffer, package.challenge, 
    package.challenge_length ); 

  status = send_handshake_message( connection, SSL_MT_CLIENT_HELLO, 
    send_buffer, buf_len, parameters ); 
 
  free( package.cipher_specs ); 
  free( package.session_id ); 
  free( package.challenge ); 
  free( send_buffer ); 

  return status; 
}

static int parse_server_hello( SSLParameters *parameters, 
                               unsigned char *buffer ) 
{ 
  int i, j; 
  int status = 0; 
  ServerHello package; 

  buffer = read_buffer( &package.session_id_hit, buffer, 1 ); 
  buffer = read_buffer( &package.certificate_type, buffer, 1 ); 
  buffer = read_buffer( &package.server_version_major, buffer, 1 ); 
  buffer = read_buffer( &package.server_version_minor, buffer, 1 ); 
  buffer = read_buffer( ( void * ) &package.certificate_length, 
    buffer, 2 ); 
  package.certificate_length = ntohs( package.certificate_length ); 
  buffer = read_buffer( ( void * ) &package.cipher_specs_length, 
    buffer, 2 ); 
  package.cipher_specs_length = ntohs( package.cipher_specs_length ); 
  buffer = read_buffer( ( void * ) &package.connection_id_length, 
    buffer, 2 ); 
  package.connection_id_length = ntohs( package.connection_id_length ); 

  // Only one of these was ever defined 
  if ( package.certificate_type == SSL_CT_X509_CERTIFICATE ) 
  {
    init_x509_certificate( &package.certificate );
    if ( status = parse_x509_certificate( buffer, 
         package.certificate_length, &package.certificate ) ) 
    { 
      // Abort immediately if there's a problem reading the certificate 
      return status; 
    } 
  } 
  else 
  { 
    printf( "Error - unrecognized certificate type %d\n", 
            package.certificate_type ); 
    status = -1; 
    return status; 
  } 
  
  buffer += package.certificate_length; 
  package.cipher_specs = malloc( package.cipher_specs_length ); 
  buffer = read_buffer( package.cipher_specs, buffer, 
    package.cipher_specs_length ); 
  package.connection_id = malloc( package.connection_id_length ); 
  buffer = read_buffer( package.connection_id, buffer, 
    package.connection_id_length ); 
 
  parameters->got_server_hello = 1; 
  // Copy connection ID into parameter state; this is needed for key 
  // computation, next 
  parameters->connection_id_len = package.connection_id_length; 
  parameters->connection_id = malloc( parameters->connection_id_len ); 
  memcpy( parameters->connection_id, package.connection_id, 
    parameters->connection_id_len ); 

  // cycle through the list of cipher specs until one is found that 
  // matches 
  // XXX this will match the last one on the list 
  for ( i = 0; i < NUM_CIPHER_SPECS; i++ ) 
  { 
    for ( j = 0; j < package.cipher_specs_length; j++ ) 
    { 
      if ( !memcmp( package.cipher_specs + ( j * 3 ), 
                    &specs[ i ].cipher_spec_code, 3 ) ) 
      { 
        parameters->proposed_cipher_spec = &specs[ i ]; 
        break; 
      } 
    } 
  } 
  
  // TODO validate the certificate/Check expiration date/Signer
  copy_huge( parameters->server_public_key.modulus, 
    package.certificate.tbsCertificate.subjectPublicKeyInfo.
    rsa_public_key.modulus ); 
  copy_huge( parameters->server_public_key.exponent,    
    package.certificate.tbsCertificate.subjectPublicKeyInfo.
    rsa_public_key.exponent ); 

  free( package.cipher_specs ); 
  free( package.connection_id ); 
  free_x509_certificate( &package.certificate ); 

  return status; 
}

static void compute_keys( SSLParameters *parameters ) 
{ 
  int i; 
  digest_ctx md5_digest; 
  int key_material_len; 
  unsigned char *key_material, *key_material_ptr; 
  char counter = '0'; 

  key_material_len = parameters->proposed_cipher_spec->key_size * 2; 
  key_material_ptr = key_material = malloc( key_material_len ); 
  parameters->master_key = malloc( 
    parameters->proposed_cipher_spec->key_size ); 

  for ( i = 0; i < parameters->proposed_cipher_spec->key_size; i++ ) 
  { 
    // XXX should be random
    parameters->master_key[ i ] = i; 
  } 

// Technically wrong per the 1995 draft specification, but removed to 
// maintain compatibility
#if 0
  if ( key_material_len <= 16 ) 
  { 
    counter = '\0'; // don't use the counter here 
  } 
#endif

  while ( key_material_len ) 
  { 
    new_md5_digest( &md5_digest ); 

    update_digest( &md5_digest, parameters->master_key, 
      parameters->proposed_cipher_spec->key_size ); 
    if ( counter ) 
    { 
      update_digest( &md5_digest, &counter, 1 ); 
      counter++; 
    } 
    update_digest( &md5_digest, parameters->challenge, CHALLENGE_LEN ); 
    update_digest( &md5_digest, parameters->connection_id, 
      parameters->connection_id_len ); 

    finalize_digest( &md5_digest ); 

    memcpy( key_material_ptr, md5_digest.hash, MD5_BYTE_SIZE ); 
    key_material_ptr += MD5_BYTE_SIZE; 
    key_material_len -= MD5_BYTE_SIZE; 
  } 
  
  parameters->read_key = malloc( 
    parameters->proposed_cipher_spec->key_size ); 
  parameters->write_key = malloc( 
    parameters->proposed_cipher_spec->key_size ); 
  memcpy( parameters->read_key, key_material, 
    parameters->proposed_cipher_spec->key_size ); 
  memcpy( parameters->write_key, key_material + 
    parameters->proposed_cipher_spec->key_size, 
    parameters->proposed_cipher_spec->key_size ); 

  // Compute IV's (or, for stream cipher, initialize state vector)
  if ( parameters->proposed_cipher_spec->cipher_spec_code == 
       SSL_CK_RC4_128_WITH_MD5 )
  {
    rc4_state *read_state = malloc( sizeof( rc4_state ) );
    rc4_state *write_state = malloc( sizeof( rc4_state ) );
    read_state->i = read_state->j = write_state->i = write_state->j = 0;
    parameters->read_iv = NULL;
    parameters->write_iv = NULL;
    parameters->read_state = read_state;
    parameters->write_state = write_state;
    memset( read_state->S, '\0', RC4_STATE_ARRAY_LEN );
    memset( write_state->S, '\0', RC4_STATE_ARRAY_LEN );
  }
  else
  {
    parameters->read_state = NULL;
    parameters->write_state = NULL;
    parameters->read_iv = malloc( 
      parameters->proposed_cipher_spec->IV_size ); 
    parameters->write_iv = malloc( 
      parameters->proposed_cipher_spec->IV_size ); 

    for ( i = 0; i < parameters->proposed_cipher_spec->IV_size; i++ ) 
    { 
      // XXX these should be random 
      parameters->read_iv[ i ] = i; 
      parameters->write_iv[ i ] = i; 
    }
  } 

  free( key_material ); 
} 

static int parse_server_error( SSLParameters *parameters, 
                               unsigned char *buffer ) 
{ 
  unsigned short error_code; 

  memcpy( &error_code, buffer, sizeof( unsigned short ) ); 
  error_code = ntohs( error_code ); 

  switch ( error_code ) 
  { 
    case SSL_PE_NO_CIPHER: 
      fprintf( stderr, "No common cipher.\n" ); 
      break; 
    default: 
      fprintf( stderr, "Unknown or unexpected error %d.\n", 
        error_code ); 
      break; 
  } 

  return error_code;
} 

static int send_client_master_key( int connection, 
                                   SSLParameters *parameters ) 
{ 
  int status = 0; 
  unsigned char *send_buffer, *write_buffer; 
  int buf_len; 
  unsigned short network_number; 
  ClientMasterKey package; 
  
  memcpy( package.cipher_kind, 
    &parameters->proposed_cipher_spec->cipher_spec_code, 3 ); 
  package.clear_key_len = 0;  // not supporting export ciphers 
  package.encrypted_key_len = rsa_encrypt( parameters->master_key, 
    parameters->proposed_cipher_spec->key_size, 
    &package.encrypted_key, &parameters->server_public_key ); 
  package.key_arg_len = parameters->proposed_cipher_spec->IV_size; 
  
  package.clear_key = malloc( sizeof( unsigned char ) * 
    package.clear_key_len ); 
  package.key_arg = malloc( sizeof( unsigned char ) * 
    package.key_arg_len ); 
  
  memcpy( package.key_arg, parameters->read_iv, 
    parameters->proposed_cipher_spec->IV_size ); 

  buf_len = sizeof( unsigned char ) * 3 + 
    sizeof( unsigned short ) * 3 + 
    package.clear_key_len + 
    package.encrypted_key_len + 
    package.key_arg_len; 
    
  send_buffer = write_buffer = malloc( buf_len ); 

  write_buffer = append_buffer( write_buffer, package.cipher_kind, 3 ); 
  network_number = htons( package.clear_key_len ); 
  write_buffer = append_buffer( write_buffer, 
    ( void * ) &network_number, 2 ); 
  network_number = htons( package.encrypted_key_len ); 
  write_buffer = append_buffer( write_buffer, 
    ( void * ) &network_number, 2 );
  network_number = htons( package.key_arg_len ); 
  write_buffer = append_buffer( write_buffer, 
    ( void * ) &network_number, 2 ); 
  write_buffer = append_buffer( write_buffer, package.clear_key, 
    package.clear_key_len ); 
  write_buffer = append_buffer( write_buffer, package.encrypted_key, 
    package.encrypted_key_len ); 
  write_buffer = append_buffer( write_buffer, package.key_arg, 
    package.key_arg_len ); 

  status = send_handshake_message( connection, 
    SSL_MT_CLIENT_MASTER_KEY, send_buffer, buf_len, parameters ); 

  free( package.clear_key ); 
  free( package.encrypted_key ); 
  free( package.key_arg ); 
  free( send_buffer ); 

  return status; 
}

static int send_client_finished( int connection, 
                                 SSLParameters *parameters ) 
{ 
  int status = 0; 
  unsigned char *send_buffer, *write_buffer; 
  int buf_len; 
  ClientFinished package; 

  package.connection_id = malloc( parameters->connection_id_len ); 
  memcpy( package.connection_id, parameters->connection_id, 
    parameters->connection_id_len ); 

  buf_len = parameters->connection_id_len; 
  write_buffer = send_buffer = malloc( buf_len ); 

  write_buffer = append_buffer( write_buffer, package.connection_id, 
    parameters->connection_id_len ); 

  status = send_handshake_message( connection, SSL_MT_CLIENT_FINISHED,
    send_buffer, buf_len, parameters ); 

  free( send_buffer ); 
  free( package.connection_id ); 

  return status; 
} 

static int parse_server_verify( SSLParameters *parameters, 
                                const unsigned char *buf ) 
{ 
  ServerVerify package; 

  memcpy( package.challenge, buf, CHALLENGE_LEN ); 

  parameters->got_server_verify = 1; 

  return ( !memcmp( parameters->challenge, package.challenge, 
    CHALLENGE_LEN ) ); 
} 

static int parse_server_finished( SSLParameters *parameters, 
                                  const unsigned char *buf, 
                                  int buf_len ) 
{ 
  ServerFinished package; 

  package.session_id = malloc( buf_len - 1 ); 
  memcpy( package.session_id, buf, buf_len - 1 ); 

  parameters->got_server_finished = 1; 

  free( package.session_id ); 

  return 0; 
} 

static int verify_mac( const unsigned char *data, 
                       int data_len, 
                       const unsigned char *mac, 
                       int mac_len, 
                       SSLParameters *parameters ) 
{ 
  digest_ctx ctx; 
  int sequence_number; 

  parameters->active_cipher_spec->new_digest( &ctx ); 

  update_digest( &ctx, parameters->read_key, 
    parameters->active_cipher_spec->key_size ); 
  update_digest( &ctx, data, data_len ); 
  sequence_number = htonl( parameters->read_sequence_number ); 
  update_digest( &ctx, ( unsigned char * ) &sequence_number, 
    sizeof( int ) ); 
  finalize_digest( &ctx ); 

  return ( !memcmp( ctx.hash, mac, mac_len ) ); 
}

static int receive_ssl_message( int connection, 
                                char *target_buffer, 
                                int target_bufsz, 
                                SSLParameters *parameters ) 
{ 
  int status = 0; 
  unsigned short message_len; 
  unsigned short bytes_read; 
  unsigned short remaining; 
  unsigned char *buffer, *bufptr; 
  unsigned char padding_len = 0; 

  // New message - read the length first 
  if ( recv( connection, &message_len, 2, 0 ) <= 0 ) 
  { 
    return -1; 
  } 
    
  message_len = ntohs( message_len ); 

  if ( message_len & 0x8000 ) 
  { 
    // two-byte length 
    message_len &= 0x7FFF; 
  } 
  else 
  { 
    // three-byte length, include a padding value 
    if ( recv( connection, &padding_len, 1, 0 ) <= 0 ) 
    { 
      return -1; 
    } 
  } 

  // Now read the rest of the message. This will fail if enough memory 
  // isn't available, but this really should never be the case. 
  bufptr = buffer = malloc( message_len ); 
  remaining = message_len; 
  bytes_read = 0; 
  while ( remaining ) 
  { 
    if ( ( bytes_read = recv( connection, bufptr, 
           remaining, 0 ) ) <= 0 ) 
    { 
      return -1; 
    } 
    bufptr += bytes_read; 
    remaining -= bytes_read; 
  } 

  // Decrypt if a cipher spec is active 
  if ( parameters->active_cipher_spec != NULL ) 
  { 
    unsigned char *decrypted = malloc( message_len ); 
    int mac_len = parameters->active_cipher_spec->hash_size; 
    parameters->active_cipher_spec->bulk_decrypt( buffer, message_len,
      decrypted,
      parameters->read_state ? parameters->read_state : 
                               parameters->read_iv,
      parameters->read_key ); 
    if ( !verify_mac( decrypted + mac_len, message_len - mac_len, 
                      decrypted,  mac_len, parameters  ) ) 
    { 
      return -1; 
    } 
    free( buffer ); 
    buffer = malloc( message_len - mac_len - padding_len ); 
    memcpy( buffer, decrypted + mac_len, 
      message_len - mac_len - padding_len ); 
    message_len = message_len - mac_len, padding_len; 

    free( decrypted ); 
  } 
    
  parameters->read_sequence_number++; 

  if ( !parameters->handshake_finished ) 
  { 
    switch ( buffer[ 0 ] ) 
    { 
      case SSL_MT_ERROR: 
        status = parse_server_error( parameters, buffer + 1 ); 
        return -1; 
      case SSL_MT_SERVER_HELLO: 
        status = parse_server_hello( parameters, buffer + 1 ); 
        if ( status == -1 ) 
        { 
          send_error( connection, 
                      SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE,
                      parameters ); 
        } 
        break; 
      case SSL_MT_SERVER_VERIFY: 
        status = parse_server_verify( parameters, buffer + 1 ); 
        break; 
      case SSL_MT_SERVER_FINISHED: 
        status = parse_server_finished( parameters, buffer + 1, 
          message_len ); 
        break; 
      default: 
        printf( "Skipping unrecognized handshake message %d\n", 
          buffer[ 0 ] ); 
        break; 
    } 
  } 
  else 
  { 
    // If the handshake is finished, the app should be expecting data; 
    // return it 
    if ( message_len > target_bufsz ) 
    { 
      memcpy( target_buffer, buffer, target_bufsz ); 
      status = target_bufsz; 

      // Store the remaining data so that the next "read" call just 
      // picks it up 
      parameters->unread_length = message_len - target_bufsz; 
      parameters->unread_buffer = malloc( parameters->unread_length ); 
      memcpy( parameters->unread_buffer, buffer + target_bufsz, 
              parameters->unread_length ); 
    } 
    else 
    { 
      memcpy( target_buffer, buffer, message_len ); 
      status = message_len; 
    } 
  } 

  free( buffer ); 

  return status; 
} 

int ssl_connect( int connection,
                 SSLParameters *parameters )
{
  init_parameters( parameters );
  
  if ( send_client_hello( connection, parameters ) == -1 )
  {
    return -1;
  } 
  
  while ( !parameters->got_server_hello )
  {
    // set proposed_cipher_spec from server hello
    if ( receive_ssl_message( connection, NULL, 0, parameters ) == -1 )
    {
      return -1;
    }
  } 
  
  // If proposed_cipher_spec is not set at this point, no cipher could
  // be negotiated
  if ( parameters->proposed_cipher_spec == NULL )
  {
    send_error( connection, SSL_PE_NO_CIPHER, parameters );
    return -1;
  } 
  
  compute_keys( parameters );
  
  if ( send_client_master_key( connection, parameters ) == -1 )
  {
    return -1;
  } 
  
  // From this point forward, everything is encrypted
  
  parameters->active_cipher_spec = parameters->proposed_cipher_spec;
  parameters->proposed_cipher_spec = NULL;
  
  if ( send_client_finished( connection, parameters ) == -1 )
  {
    return -1;
  } 
  
  while ( !parameters->got_server_verify )
  {
    if ( receive_ssl_message( connection, NULL, 0, parameters ) == -1 )
    {
      return -1;
    }
  } 
  
  while ( !parameters->got_server_finished )
  {
    if ( receive_ssl_message( connection, NULL, 0, parameters ) == -1 )
    {
      return -1;
    }
  } 
  
  parameters->handshake_finished = 1;
  
  return 0;
} 

int ssl_send( int connection, const char *application_data, int length, 
              int options,  SSLParameters *parameters ) 
{ 
  return ( send_message( connection, application_data, length, 
                         parameters ) ); 
} 

int ssl_recv( int connection, char *target_buffer, int buffer_size, 
              int options, SSLParameters *parameters )
{
  return receive_ssl_message( connection, target_buffer, 
                              buffer_size, parameters );
}
