#ifndef MAIN_H_
#define MAIN_H_

extern const char* const KEY_LOCATION;
extern const char* const FILE_LOCATION;
extern const char* const ENCRYPTED_LOCATION;
extern const char* const DECRYPTED_LOCATION;

extern int BASE;
extern int BYTE;
extern int AES_KEY_LENGTH;
extern int AES_BLOCK_LENGTH;
extern int RSA_KEY_LENGTH;
extern int RSA_PADDING;
extern int MAX_FILE_SIZE;

extern const char* const TEXT_EXTENSION;
extern const char* const AES_KEY_EXTENSION;
extern const char* const AES_ENCRYPTION_EXTENSION;
extern const char* const RSA_PUBLIC_KEY_EXTENSION;
extern const char* const RSA_SECRET_KEY_EXTENSION;
extern const char* const RSA_ENCRYPTION_EXTENSION;
extern const char* const SHA_DIGEST_EXTENSION;
extern const char* const ENVELOPE_EXTENSION;
extern const char* const SIGNATURE_EXTENSION;
extern const char* const SEAL_EXTENSION;

extern const char* const DEFAULT_NAME;
extern const char* const DEFAULT_SENDER;
extern const char* const DEFAULT_RECEIVER;

extern const char* const BEGIN_FILE;
extern const char* const END_FILE;
extern const char* const DESCRIPTION;
extern const char* const FILE_NAME;
extern const char* const METHOD;
extern const char* const KEY_LENGTH;
extern const char* const SECRET_KEY;
extern const char* const INITIALIZATION_VECTOR;
extern const char* const MODULUS;
extern const char* const PUBLIC_EXPONENT;
extern const char* const PRIVATE_EXPONENT;
extern const char* const SIGNATURE;
extern const char* const DATA;
extern const char* const ENVELOPE_DATA;
extern const char* const ENVELOPE_CRYPT_KEY;

#endif