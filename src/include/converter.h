#ifndef CONVERTER_H_
#define CONVERTER_H_

bool Base64Encode(unsigned char* message, int messageLen, char** buffer);
bool Base64Decode(char* b64message, unsigned char** buffer);
int EncodeB64(void *input, unsigned char** output, int length);
int DecodeB64(void *input, unsigned char** output, int length);
int CalcDecodeLength(const char* b64input);
unsigned char* CharToHex(unsigned char *input, int *length);
unsigned char* HexToChar(unsigned char *input, int length);
int CharToInt(char* number);
char* IntToChar(int number, int* length);
char* IntToHex(int number);
int HexToInt(char* hexNumber);
BIGNUM* bignum_base64_decode(const char* base64bignum);
unsigned char* bignum_base64_encode(const BIGNUM* base64bignum);
EVP_PKEY* RSA_fromBase64Public(const char* modulus_b64, const char* publicExponent);
EVP_PKEY* RSA_fromBase64Private(const char* modulus_b64, const char* privateExponent, const char* publicExponent);
#endif