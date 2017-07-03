#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

unsigned char* GUIGenerateAESKey(int keyLength, int blockLength, char* fileName);
bool GenerateAESKey(int keyLength, int blockLength, unsigned char** aesKey, unsigned char** aesIV);
void GUIAESEncryption(char* keyFile, char* textFile, char* encTextFile, char print);
int AESEncryption(char *plainText, int plainTextLen, unsigned char *key, int keyLen, unsigned char *iv, unsigned char **cipherText);
void GUIAESDecryption(char* keyFile, char* textFile, char* encTextFile, char print);
int AESDecryption(unsigned char *cipherText, int cipherTextLen, unsigned char *key, int keyLen, unsigned char *iv, char **plainText);
bool GUIGenerateRSAKeys(int keyLength, const char* fileName, char print);
bool GenerateRSAKeys(int keyLength,  unsigned char** modulus, unsigned char** pkey, unsigned char** skey);
bool GUIRSAEncryption(char* keyFile, char* textFile, char* encTextFile, char private, char print);
bool RSAEncryption(char *plaintext, int plaintextLen, int keyLength, char *publicKey, char *secretKey, char *modulus, int *encLen, unsigned char **cipherText, char private);
bool GUIRSADecryption(char* keyFile, char* encTextFile, char* textFile, char public, char print);
bool RSADecryption(unsigned char *cipherText, int encLen, int keyLength, char *publicKey, char *secretKey, char *modulus, int *plainTextLen, unsigned char **plainText, char public);
bool GUISHADigest(char* textFile, char* digestFile, unsigned char** digest, int* digestLen, char whichFunction, char print);
bool SHADigest(const char *message, int messageLen, unsigned char **digest, int *digestLen);
bool SHA2Digest(const char *message, int messageLen, unsigned char **digest, int *digestLen);
bool GUISignature(char* inputFile, char* keyFile, char* signatureFile, char print);
bool Signature(char* plainText, int keyLength, char* modulus, char* publicKey, char* secretKey, unsigned char** signature, int* signatureLength);
bool GUICheckSignature(char* inputFile, char* signatureFile, char* keyFile, bool* valid, char print);
bool CheckSignature(char* text, unsigned char* signature, int signatureLength, int keyLength, char* publicKey, char* modulus, bool* valid, char** decrypted, int* decryptedLen);
bool GUIEnvelope(char* inputFile, char* keyFile, char* envelopeFile, char print);
bool Envelope(char* plainText, int keyLength, char* modulus, char* publicKey, unsigned char** envelopeData, int* envelopeDataLen, unsigned char** envelopeCryptKey, int* envelopeCryptKeyLen);
bool GUIOpenEnvelope(char* envelopeFile, char* keyFile, char* outputFile, char print);
bool OpenEnvelope(unsigned char* envelopeData, int keyLength, char* publicKey, char* secretKey, char* modulus, unsigned char* envelopeCryptKey, char** text, int* textLength);

#endif