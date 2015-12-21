#ifndef SSL_H
#define SSL_H

#include "digest.h"
#include "x509.h"

typedef struct
{
  int cipher_spec_code;

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
CipherSpec;

#define SSL_CK_RC4_128_WITH_MD5               0x800001
#define SSL_CK_DES_64_CBC_WITH_MD5            0x400006
#define SSL_CK_DES_192_EDE3_CBC_WITH_MD5      0xc00007
#define SSL_CK_RC4_128_EXPORT40_WITH_MD5      0x800002
#define SSL_CK_RC2_128_CBC_WITH_MD5           0x800003
#define SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5  0x800004
#define SSL_CK_IDEA_128_CBC_WITH_MD5          0x800005

#define SSL_PE_NO_CIPHER                    0x0100
#define SSL_PE_NO_CERTIFICATE               0x0200
#define SSL_PE_BAD_CERTIFICATE              0x0400
#define SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE 0x0600

#define SSL_CT_X509_CERTIFICATE  1

#define SSL_MT_ERROR                    0
#define SSL_MT_CLIENT_HELLO             1
#define SSL_MT_CLIENT_MASTER_KEY        2
#define SSL_MT_CLIENT_FINISHED          3
#define SSL_MT_SERVER_HELLO             4
#define SSL_MT_SERVER_VERIFY            5
#define SSL_MT_SERVER_FINISHED          6

// Technically, this is a variable-length parameter; the client can send
// between 16 and 32 bytes. Here, it’s left as a fixed-length 
// parameter.
#define CHALLENGE_LEN 16

typedef struct
{
  CipherSpec *active_cipher_spec;
  CipherSpec *proposed_cipher_spec;

  // Flow-control variables
  int got_server_hello;
  int got_server_verify;
  int got_server_finished;
  int handshake_finished;
  int connection_id_len;

  rsa_key server_public_key;

  unsigned char challenge[ CHALLENGE_LEN ];
  unsigned char *master_key;   
  unsigned char *connection_id;

  void *read_state;
  void *write_state;
  unsigned char *read_key;
  unsigned char *write_key;
  unsigned char *read_iv;
  unsigned char *write_iv;
  int read_sequence_number;
  int write_sequence_number;

  unsigned char *unread_buffer;
  int           unread_length;
}
SSLParameters;

typedef struct 
{ 
  unsigned char version_major; 
  unsigned char version_minor; 
  unsigned short cipher_specs_length; 
  unsigned short session_id_length; 
  unsigned short challenge_length; 
  unsigned char *cipher_specs; 
  unsigned char *session_id; 
  unsigned char *challenge; 
} 
ClientHello; 

typedef struct 
{ 
  unsigned char session_id_hit; 
  unsigned char certificate_type; 
  unsigned char server_version_major; 
  unsigned char server_version_minor; 
  unsigned short certificate_length; 
  unsigned short cipher_specs_length; 
  unsigned short connection_id_length; 
  signed_x509_certificate certificate; 
  unsigned char *cipher_specs; 
  unsigned char *connection_id; 
} 
ServerHello; 

typedef struct 
{ 
  unsigned char cipher_kind[ 3 ]; 
  unsigned short clear_key_len; 
  unsigned short encrypted_key_len; 
  unsigned short key_arg_len; 
  unsigned char *clear_key; 
  unsigned char *encrypted_key; 
  unsigned char *key_arg; 
} 
ClientMasterKey; 

typedef struct 
{ 
  unsigned char *connection_id; 
} 
ClientFinished; 

typedef struct 
{ 
  unsigned char challenge[ CHALLENGE_LEN ]; 
} 
ServerVerify;

typedef struct 
{ 
  unsigned char *session_id; 
} 
ServerFinished; 

int ssl_connect( int connection, SSLParameters *parameters );

int ssl_send( int connection, const char *application_data, int length, 
              int options, SSLParameters *parameters );

int ssl_recv( int connection, char *target_buffer, int buffer_size, 
              int options, SSLParameters *parameters );

#endif
