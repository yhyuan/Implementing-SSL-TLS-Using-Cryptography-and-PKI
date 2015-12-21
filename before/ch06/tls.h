#ifndef TLS_H
#define TLS_H

#include "digest.h"
#include "x509.h"
#include "dh.h"

typedef enum 
{ 
  TLS_NULL_WITH_NULL_NULL               = 0x0000,
  TLS_RSA_WITH_NULL_MD5                 = 0x0001,
  TLS_RSA_WITH_NULL_SHA                 = 0x0002,
  TLS_RSA_EXPORT_WITH_RC4_40_MD5        = 0x0003,
  TLS_RSA_WITH_RC4_128_MD5              = 0x0004,
  TLS_RSA_WITH_RC4_128_SHA              = 0x0005,
  TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5    = 0x0006,
  TLS_RSA_WITH_IDEA_CBC_SHA             = 0x0007,
  TLS_RSA_EXPORT_WITH_DES40_CBC_SHA     = 0x0008,
  TLS_RSA_WITH_DES_CBC_SHA              = 0x0009,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA         = 0x000A,
  TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  = 0x000B,
  TLS_DH_DSS_WITH_DES_CBC_SHA           = 0x000C,
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = 0x000D,
  TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x000E,
  TLS_DH_RSA_WITH_DES_CBC_SHA           = 0x000F,
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = 0x0010,
  TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
  TLS_DHE_DSS_WITH_DES_CBC_SHA          = 0x0012,
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = 0x0013,
  TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
  TLS_DHE_RSA_WITH_DES_CBC_SHA          = 0x0015,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = 0x0016,
  TLS_DH_anon_EXPORT_WITH_RC4_40_MD5    = 0x0017,
  TLS_DH_anon_WITH_RC4_128_MD5          = 0x0018,
  TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
  TLS_DH_anon_WITH_DES_CBC_SHA          = 0x001A,
  TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = 0x001B,

  // 1C & 1D were used by SSLv3 to describe Fortezza suites
  // End of list of algorithms defined by RFC 2246

  // These are all defined in RFC 4346 (v1.1), not 2246 (v1.0)
  //
  TLS_KRB5_WITH_DES_CBC_SHA           = 0x001E,
  TLS_KRB5_WITH_3DES_EDE_CBC_SHA      = 0x001F,
  TLS_KRB5_WITH_RC4_128_SHA           = 0x0020,
  TLS_KRB5_WITH_IDEA_CBC_SHA          = 0x0021,
  TLS_KRB5_WITH_DES_CBC_MD5           = 0x0022,
  TLS_KRB5_WITH_3DES_EDE_CBC_MD5      = 0x0023,
  TLS_KRB5_WITH_RC4_128_MD5           = 0x0024,
  TLS_KRB5_WITH_IDEA_CBC_MD5          = 0x0025,
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026,
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027,
  TLS_KRB5_EXPORT_WITH_RC4_40_SHA     = 0x0028,
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029,
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A,
  TLS_KRB5_EXPORT_WITH_RC4_40_MD5     = 0x002B,

  // TLS_AES ciphersuites - RFC 3268
  TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA   = 0x0030,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA   = 0x0031,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033,
  TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034,
  TLS_RSA_WITH_AES_256_CBC_SHA      = 0x0035,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA   = 0x0036,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA   = 0x0037,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA  = 0x0038,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x0039,
  TLS_DH_anon_WITH_AES_256_CBC_SHA  = 0x003A,
} CipherSuiteIdentifier;

typedef struct
{
  CipherSuiteIdentifier id;

  int                   block_size;
  int                   IV_size;
  int                   key_size;
  int                   hash_size;

  void (*bulk_encrypt)( const unsigned char *plaintext,
                        const int plaintext_len,
                        unsigned char ciphertext[],
                        void *iv,
                        const unsigned char *key );
  void (*bulk_decrypt)( const unsigned char *ciphertext,
                        const int ciphertext_len,
                        unsigned char plaintext[],
                        void *iv,
                        const unsigned char *key );
  void (*new_digest)( digest_ctx *context );
}
CipherSuite;

typedef struct
{
  unsigned char *MAC_secret;
  unsigned char *key;
  unsigned char *IV;
  CipherSuiteIdentifier suite;
  unsigned long         seq_num;
}
ProtectionParameters;

#define TLS_VERSION_MAJOR 3
#define TLS_VERSION_MINOR 1

#define MASTER_SECRET_LENGTH  48
typedef unsigned char master_secret_type[ MASTER_SECRET_LENGTH ];

#define RANDOM_LENGTH 32
typedef unsigned char random_type[ RANDOM_LENGTH ];

typedef struct
{ 
  master_secret_type    master_secret;
  random_type           client_random;
  random_type           server_random;

  ProtectionParameters  pending_send_parameters;
  ProtectionParameters  pending_recv_parameters;
  ProtectionParameters  active_send_parameters;
  ProtectionParameters  active_recv_parameters;

  // RSA public key, if supplied
  public_key_info       server_public_key;

  // DH public key, if supplied (either in a certificate or ephemerally)
  // Note that a server can legitimately have an RSA key for signing and 
  // a DH key for key exchange (e.g. DHE_RSA)
  dh_key                server_dh_key;
  int                   server_hello_done;
  int                   server_finished;
  digest_ctx            md5_handshake_digest;
  digest_ctx            sha1_handshake_digest;
  char                  *unread_buffer;
  int                   unread_length;
}
TLSParameters;

/** This lists the type of higher-level TLS protocols that are defined */
typedef enum { 
  content_change_cipher_spec = 20,
  content_alert = 21, 
  content_handshake = 22,
  content_application_data = 23
} 
ContentType;

typedef enum { warning = 1, fatal = 2 } AlertLevel;

/**
 * Enumerate all of the error conditions specified by TLS.
 */
typedef enum
{
  close_notify = 0,
  unexpected_message = 10,
  bad_record_mac = 20,
  decryption_failed = 21,
  record_overflow = 22,
  decompression_failure = 30,
  handshake_failure = 40,
  bad_certificate = 42,
  unsupported_certificate = 43,
  certificate_revoked = 44,
  certificate_expired = 45,
  certificate_unknown = 46,
  illegal_parameter = 47,
  unknown_ca = 48,
  access_denied = 49,
  decode_error = 50,
  decrypt_error = 51,
  export_restriction = 60,
  protocol_version = 70,
  insufficient_security = 71,
  internal_error = 80,
  user_canceled = 90,
  no_renegotiation = 100
}
AlertDescription;

typedef struct
{
  unsigned char level;
  unsigned char description;
}
Alert;

typedef struct
{
  unsigned char major, minor;
}
ProtocolVersion;

/**
 * Each packet to be encrypted is first inserted into one of these structures.
 */
typedef struct
{
  unsigned char   type;
  ProtocolVersion version;
  unsigned short  length;
}
TLSPlaintext;

typedef struct
{
  unsigned int  gmt_unix_time;
  unsigned char  random_bytes[ 28 ];
}
Random;

/**
 * Handshake message types (section 7.4)
 */
typedef enum
{
  hello_request = 0,
  client_hello = 1,
  server_hello = 2,
  certificate = 11,
  server_key_exchange = 12,
  certificate_request = 13,
  server_hello_done = 14,
  certificate_verify = 15,
  client_key_exchange = 16,
  finished = 20
}
HandshakeType;

/**
 * Handshake record definition (section 7.4)
 */
typedef struct
{ 
  unsigned char         msg_type;
  unsigned int        length;       // 24 bits(!)
}
Handshake;

/**
 * Section 7.4.1.2
 */
typedef struct
{
  ProtocolVersion client_version;
  Random random;
  unsigned char session_id_length;
  unsigned char *session_id;
  unsigned short cipher_suites_length;
  unsigned short *cipher_suites;
  unsigned char compression_methods_length;
  unsigned char *compression_methods;
}
ClientHello;

typedef struct
{
  ProtocolVersion   server_version;
  Random            random;
  unsigned char     session_id_length;
  unsigned char     session_id[ 32 ]; // technically, this len should be dynamic.
  unsigned short    cipher_suite;
  unsigned char     compression_method;
}
ServerHello;

/**
 * Negotiate an TLS channel on an already-established connection 
 * (or die trying).
 * @return 1 if successful, 0 if not.
 */
int tls_connect( int connection,
                 TLSParameters *parameters );

/**
 * Send data over an established TLS channel.  tls_connect must already 
 * have been called with this socket as a parameter.
 */
int tls_send( int connection, 
              const char *application_data, 
              int length, 
              int options,
              TLSParameters *parameters );
/**
 * Received data from an established TLS channel.
 */
int tls_recv( int connection, 
              char *target_buffer, 
              int buffer_size, 
              int options,
              TLSParameters *parameters );

/**
 * Orderly shutdown of the TLS channel (note that the socket itself will 
 * still be open after this is called).
 */
int tls_shutdown( int connection, TLSParameters *parameters );

#endif
