#include "allInclusions.h"

char* keyIvSeparator = "\n1\n";
int envelopeAesKeyLength = 128;
int envelopeBlockLength = 128;

unsigned char* GUIGenerateAESKey(int keyLength, int blockLength, char* fileName)
{
    unsigned char* aesKey = NULL;
    unsigned char* aesIV = NULL;
    unsigned char* keys[2];
    char* keyLengths[2];
    char* keyPath = DefinePath(KEY_LOCATION, fileName, AES_KEY_EXTENSION);

    if(keyLength != 128 && keyLength != 192 && keyLength != 256)
    {
        ErrorHandler(AESKEYLENGTH, "key has to be either 128, 192, or 256 bits");
        return NULL;
    }
    if(blockLength != 128)
    {
        ErrorHandler(AESIVLENGTH, "IV has to be 128 bits");
        return NULL;
    }

    bool success = GenerateAESKey(keyLength, blockLength, &aesKey, &aesIV);
    if(success)
    {
        int numOfCharsKey = keyLength/BYTE;
        int numOfCharsIV = blockLength/BYTE;
        keys[0] = CharToHex(aesKey, &numOfCharsKey);
        keys[1] = CharToHex(aesIV, &numOfCharsIV);
        keyLengths[0]= IntToHex(keyLength);
        keyLengths[1] = IntToHex(blockLength);

        PrepareAndSave(AES_KEY, keys, NULL, keyLengths,  NULL, keyPath);
    }

    return aesKey;
}

bool GenerateAESKey(int keyLength, int blockLength, unsigned char** aesKey, unsigned char** aesIV)
{
    int numOfCharsKey = keyLength/BYTE;
    int numOfCharsIV = blockLength/BYTE;

    unsigned char* tempAesKey = (unsigned char*)malloc(sizeof(unsigned char) * (numOfCharsKey + 1));
    unsigned char* tempAesIV = (unsigned char*)malloc(sizeof(unsigned char) * (numOfCharsIV + 1));

    memset(tempAesKey, 0, numOfCharsKey + 1);
    memset(tempAesIV, 0, numOfCharsIV + 1);

    if (!RAND_bytes(tempAesKey, numOfCharsKey))
        tempAesKey = NULL;
    if (!RAND_bytes(tempAesIV, numOfCharsIV))
        tempAesIV = NULL;

    if(tempAesKey == NULL || tempAesIV == NULL)
    {
        free(tempAesKey);
        free(tempAesIV);
        *aesKey = NULL;
        *aesIV = NULL;
        return false;
    }

    *aesKey = tempAesKey;
    *aesIV = tempAesIV;

    return true;
}

void GUIAESEncryption(char* keyFile, char* textFile, char* encTextFile, char print)
{
    char* keyFilePath = DefinePath(KEY_LOCATION, keyFile, AES_KEY_EXTENSION);
    char* textFilePath = DefinePath(FILE_LOCATION, textFile, TEXT_EXTENSION);
    char* encTextFilePath = DefinePath(ENCRYPTED_LOCATION, encTextFile, AES_ENCRYPTION_EXTENSION);

    unsigned char** data = NULL;
    unsigned char* key = NULL;
    unsigned char* iv = NULL;
    char* text = NULL;

    int textLen = ReadFile(textFilePath, (unsigned char**)&text, 0);

    unsigned char** keys = NULL;
    char** keyLengths = NULL;

    bool success = ReadAndPrepare(AES_KEY, keyFilePath, &keys, NULL, &keyLengths);
    if(!success || *keys == NULL || *keyLengths == NULL || text == NULL)
        return;
    key = HexToChar(*keys, FieldSize(*keys));
    iv = HexToChar(*(keys + 1), FieldSize(*(keys + 1)));

    int keyLen = HexToInt(*keyLengths);
    int ivLen = HexToInt(*(keyLengths + 1));

    unsigned char* encText = (unsigned char*) calloc(3 * textLen, sizeof(unsigned char));

    if(print == 1)
    {
        printf("\nAES key: ");
        HexPrint(key, keyLen/BYTE);
        printf("\nIV key: ");
        HexPrint(iv, ivLen/BYTE);
        printf("\nClear text:\n%s\n", text);
    }
    int encLen = AESEncryption(text, textLen, key, keyLen, iv, &encText);

    if(encLen != 0)
    {
        data = malloc(sizeof(char*));
        data = &encText;
        PrepareAndSave(AES_ENCRYPTION, NULL, data, keyLengths, textFilePath, encTextFilePath);
        if(print == 1)
            printf("\nEncrypted text:\n%s\n", *data);
    }
    free(encText);
    free(text);
    free(key);
    free(iv);
    free(keys);
    free(keyLengths);
    return;
}

int AESEncryption(char *plainText, int plainTextLen, unsigned char *key, int keyLen, unsigned char *iv, unsigned char **cipherText)
{
    bool error = false;
    int len;
    int cipherTextLen = 0;
    EVP_CIPHER_CTX *ctx;

    if(!(ctx = EVP_CIPHER_CTX_new())) 
    {
        ErrorHandler(EVPLIBRARY, NULL);
        return 0;
    }

    switch(keyLen)
    {
        case 128:
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *)key, (const unsigned char *)iv))
                error = true;
            break;
        case 192:
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, (const unsigned char *)key, (const unsigned char *)iv))
                error = true;
            break;
        case 256:
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *)key, (const unsigned char *)iv))
                error = true;
            break;
        default:
            ErrorHandler(AESKEYLENGTH, NULL);
            return 0;
            break;
    }

    if(error)
    {
        ErrorHandler(AESINIT, NULL);
        return 0;
    }

    if(1 != EVP_EncryptUpdate(ctx, *cipherText, &len, (unsigned char *)plainText, plainTextLen))
    {
        ErrorHandler(AESENCRYPT, NULL);
        return 0;
    } 
    cipherTextLen = len;

    if(1 != EVP_EncryptFinal_ex(ctx, *cipherText + cipherTextLen, &len))
    {
        ErrorHandler(AESENCRYPT, NULL);
        return 0;
    }
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    unsigned char *tempText;
    bool success = Base64Encode(*cipherText, cipherTextLen, (char**) &tempText);
    if(!success)
        return 0;
    *cipherText = tempText;
    cipherTextLen = strlen((char*)*cipherText);
    return cipherTextLen;
}

void GUIAESDecryption(char* keyFile, char* encTextFile, char* textFile, char print)
{
    char* keyFilePath = DefinePath(KEY_LOCATION, keyFile, AES_KEY_EXTENSION);
    char* encTextFilePath = DefinePath(ENCRYPTED_LOCATION, encTextFile, AES_ENCRYPTION_EXTENSION);
    char* textFilePath = DefinePath(DECRYPTED_LOCATION, textFile, TEXT_EXTENSION);

    unsigned char** keys = NULL;
    char** keyLengths = NULL;
    unsigned char* key = NULL;
    unsigned char* iv = NULL;
    unsigned char* encText = NULL;
    unsigned char** data = NULL;

    bool success = ReadAndPrepare(AES_KEY, keyFilePath, &keys, NULL, &keyLengths);
    if(!success || *keys == NULL || *keyLengths == NULL)
        return;
    key = HexToChar(*keys, FieldSize(*keys));
    iv = HexToChar(*(keys + 1), FieldSize(*(keys + 1)));
    int keyLen = HexToInt(*keyLengths);
    int ivLen = HexToInt(*(keyLengths + 1));
    
    success = ReadAndPrepare(AES_ENCRYPTION, encTextFilePath, NULL, &data, NULL);
    if(!success || *data == NULL)
        return;
    encText = *data;
    int encLen = FieldSize((char*) encText);

    char* text = (char*) calloc(encLen, sizeof(char));

    if(print == 1)
    {
        printf("\nAES key: ");
        HexPrint(key, keyLen/BYTE);
        printf("\nIV key: ");
        HexPrint(iv, ivLen/BYTE);
        printf("\nEncrypted text:\n%s\n", encText);
    }

    int textLen = AESDecryption(encText, encLen, key, keyLen, iv, &text);
    if(textLen != 0)
    {
        SaveToFile((unsigned char*) text, textLen, textFilePath, 0, 0);
        text[textLen] = '\0';
        if(print == 1)
            printf("\nDecripted text:\n%s\n", text);
    }

    free(encText);
    free(text);
    free(key);
    free(iv);
    free(data);
    free(keys);
    free(keyLengths);
    return;
}

int AESDecryption(unsigned char *cipherText, int cipherTextLen, unsigned char *key, int keyLen, unsigned char *iv, char **plainText)
{
    bool error = false;
    EVP_CIPHER_CTX *ctx;
    unsigned char *tempText;

    int len;
    int plainTextLen;

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        ErrorHandler(EVPLIBRARY, NULL);
        return 0;
    }

    switch(keyLen)
    {
        case 128:
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
                error = true;
            break;
        case 192:
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
                error = true;
            break;
        case 256:
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
                error = true;
            break;
        default:
            ErrorHandler(AESKEYLENGTH, NULL);
            return 0;
            break;
    }

    if(error)
    {
        ErrorHandler(AESINIT, NULL);
        return 0;
    }

    bool success = Base64Decode((char*) cipherText, (unsigned char**) &tempText);
    if(!success)
        return 0;

    cipherText = tempText;
    cipherTextLen = strlen((char*) tempText);
   
    if(1 != EVP_DecryptUpdate(ctx, (unsigned char *) *plainText, &len, cipherText, cipherTextLen))
    {
        ErrorHandler(AESDECRYPT, NULL);
        return 0;
    }  
    plainTextLen = len;

    if(1 != EVP_DecryptFinal_ex(ctx, (unsigned char *) *plainText + plainTextLen, &len))
    {
        ErrorHandler(AESDECRYPT, NULL);
        return 0;
    }
    plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return plainTextLen;
}

bool GUIGenerateRSAKeys(int keyLength, const char* fileName, char print)
{
    if(keyLength != 1024 && keyLength != 2048 && keyLength != 3072)
    {
        ErrorHandler(RSAKEYLENGTH, "key has to be either 1024, 2048, or 3072 bits");
        return false;
    }
    char* rsaPublicFile = DefinePath(KEY_LOCATION, fileName, RSA_PUBLIC_KEY_EXTENSION);
    char* rsaSecretFile = DefinePath(KEY_LOCATION, fileName, RSA_SECRET_KEY_EXTENSION);

    unsigned char* modulus = NULL;
    unsigned char* pkey = NULL;
    unsigned char* skey = NULL;
    unsigned char* keys[3];
    char* keyLengths[1];

    bool success = GenerateRSAKeys(keyLength, &modulus, &pkey, &skey);

    if(success)
    {
        keys[0] = modulus;
        keys[1] = pkey;
        keys[2] = skey;
        keyLengths[0]= IntToHex(keyLength);
        PrepareAndSave(RSA_PUBLIC_KEY, keys, NULL, keyLengths, NULL, rsaPublicFile);
        PrepareAndSave(RSA_SECRET_KEY, keys, NULL, keyLengths, NULL, rsaSecretFile);

        if(print == 1)
        {
            printf("\nRSA keys: \n");
            printf("Modulus: \n%s\n", modulus);
            printf("Public key: \n%s\n", pkey);
            printf("Secret key: \n%s\n", skey);
        }
        return true;
    }
    return false;
}

bool GenerateRSAKeys(int keyLength, unsigned char** modulus, unsigned char** pkey, unsigned char** skey)
{
    RSA* keyPair;
    EVP_PKEY *tempPkey = NULL;
    unsigned long ee = RSA_F4; 
    keyPair= RSA_generate_key(keyLength, ee, NULL, NULL);
    if (RSA_check_key(keyPair)!=1)
    {
        ErrorHandler(RSAKEYGENERATION, NULL);
        return false;
    }
    unsigned char *n = bignum_base64_encode(keyPair->n);
    unsigned char *d = bignum_base64_encode(keyPair->d);
    unsigned char *e = bignum_base64_encode(keyPair->e);
    *modulus = n;
    *skey = d;
    *pkey = e;
    
    return true;
}

bool GUIRSAEncryption(char* keyFile, char* textFile, char* encTextFile, char private, char print)
{
    char* textFilePath = DefinePath(FILE_LOCATION, textFile, TEXT_EXTENSION);
    char* keyFilePath = DefinePath(KEY_LOCATION, textFile, AES_KEY_EXTENSION);
    char* rsaFilePath = (!private) ? DefinePath(KEY_LOCATION, keyFile, RSA_PUBLIC_KEY_EXTENSION) : DefinePath(KEY_LOCATION, keyFile, RSA_SECRET_KEY_EXTENSION);
    char* encFilePath = DefinePath(ENCRYPTED_LOCATION, encTextFile, RSA_ENCRYPTION_EXTENSION);
    char** source;
    enum FileTypes type = (!private) ? RSA_PUBLIC_KEY : RSA_SECRET_KEY;

    int keyLength;
    int encLen;
    unsigned char* encText;
    char* publicKey;
    char* secretKey = NULL;
    char* modulus;
    char* text = NULL;
    unsigned char** keys = NULL;
    char** keyLengths = NULL;
    unsigned char** secondKeys = NULL;
    char** keyLengthsSecond = NULL;
    bool success = ReadAndPrepare(type, rsaFilePath, &keys, NULL, &keyLengths);
    if(!success || *keys == NULL || *keyLengths == NULL)
        return false;
    
    keyLength = HexToInt(*keyLengths);
    encText = calloc(keyLength + 1, sizeof(unsigned char));
    modulus = (char*) *keys;
    publicKey = (char*) *(keys + 1);
    if(private)
        secretKey = (char*) *(keys + 2);

    success = ReadAndPrepare(AES_KEY, keyFilePath, &secondKeys, NULL, &keyLengthsSecond);
    if(!success || *secondKeys == NULL || *keyLengthsSecond == NULL)
    {
        success = ReadFile(textFilePath, (unsigned char**) &text, 0);
        if(!success)
            return 0;
        source = &textFilePath;
    }
    else
    {
        char* aesKey = (char *)HexToChar(*secondKeys, FieldSize(*secondKeys));
        char* aesIV = (char *)HexToChar(*(secondKeys + 1), FieldSize(*(secondKeys + 1)));
        text = (char*) calloc(strlen(aesKey) + strlen(aesIV) + strlen(keyIvSeparator) + 1 , sizeof(char*));
        strncpy(text, aesKey, strlen(aesKey));
        strncat(text, keyIvSeparator, strlen(keyIvSeparator));
        strncat(text, aesIV, strlen(aesIV));
        free(aesKey);
        free(aesIV);
        source = &keyFilePath;
    }
    
    int textSize = strlen((char*) text);
    if(textSize * BYTE > keyLength)
    {
        ErrorHandler(RSAENCODING, NULL);
        return false;
    }
    
    success = RSAEncryption(text, textSize, keyLength, publicKey, secretKey, modulus, &encLen, &encText, private);

    if(success)
    {
        unsigned char* data[1];
        data[0] = encText;
        PrepareAndSave(RSA_ENCRYPTION, NULL, data, keyLengths, *source, encFilePath);
        if(print == 1)
        {
            printf("\nRSA keys: \n");
            printf("Modulus: \n%s\n", modulus);
            if(!private)
                printf("Public exponent: \n%s\n", publicKey);
            else
                printf("Private exponent: \n%s\n", secretKey);
            printf("Clear text: \n%s\n", text);
            printf("Encrypted text: \n%s\n", encText);
        }
    }  
    free(text);
    free(encText);
    free(keyLengths);
    free(textFilePath);
    free(keyFilePath);
    free(rsaFilePath);
    free(encFilePath);
    free(keys);
    return true;
}

bool RSAEncryption(char *plaintext, int plaintextLen, int keyLength, char *publicKey, char *secretKey, char *modulus, int *encLen, unsigned char **cipherText, char private)
{
    int cipherTextLen = 0;
    unsigned char *encrypted = calloc(keyLength/BYTE + 1, sizeof(unsigned char));

    EVP_PKEY* pkey = (!private) ? RSA_fromBase64Public(modulus, publicKey) : RSA_fromBase64Private(modulus, secretKey, publicKey);
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);

    cipherTextLen = (!private) ? RSA_public_encrypt(plaintextLen, (unsigned char*) plaintext, encrypted, rsa, RSA_PKCS1_PADDING) :
                                RSA_private_encrypt(plaintextLen, (unsigned char*) plaintext, encrypted, rsa, RSA_PKCS1_PADDING);

    if(keyLength/BYTE != cipherTextLen)
    {
        ErrorHandler(RSAENCODING, NULL);
        return false;
    }
    bool success = Base64Encode(encrypted, cipherTextLen, (char**) cipherText);
    if(!success)
        return false;
    
    cipherTextLen = strlen((char*) *cipherText);
    *encLen = cipherTextLen;

    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    free(encrypted);
    return true;
}

bool GUIRSADecryption(char* keyFile, char* encTextFile, char* textFile, char public, char print)
{
    char* textFilePath = DefinePath(DECRYPTED_LOCATION, textFile, TEXT_EXTENSION);
    char* rsaKeyPath = (!public) ? DefinePath(KEY_LOCATION, keyFile, RSA_SECRET_KEY_EXTENSION) : DefinePath(KEY_LOCATION, keyFile, RSA_PUBLIC_KEY_EXTENSION);
    char* encFilePath = DefinePath(ENCRYPTED_LOCATION, encTextFile, RSA_ENCRYPTION_EXTENSION);
    enum FileTypes type = (!public) ? RSA_SECRET_KEY : RSA_PUBLIC_KEY;

    char* whichFile;
    int keyLength;
    int textLen;
    int encLen;
    unsigned char* encText;
    char* publicKey;
    char* secretKey = NULL;
    char* modulus;
    char* text = NULL;
    unsigned char** data;
    unsigned char** keys = NULL;
    char** keyLengths = NULL;
    unsigned char** secondKeys = NULL;
    char** keyLengthsSecond = NULL;
    bool success = ReadAndPrepare(type, rsaKeyPath, &keys, NULL, &keyLengths);
    if(!success || *keys == NULL || *keyLengths == NULL)
        return false;
    
    keyLength = HexToInt(*keyLengths);
    text = calloc(keyLength/BYTE + 1, sizeof(char));
    modulus = (char*) *keys;
    publicKey = (char*) *(keys + 1);
    if(!public)
        secretKey = (char*) *(keys + 2);

    success = ReadAndPrepare(RSA_ENCRYPTION, encFilePath, NULL, &data, &keyLengthsSecond);
    if(!success || *data == NULL || *keyLengthsSecond == NULL)
        return false;

    encText = *data;
    whichFile = (char*) *(data + 1);
    
    success = RSADecryption(encText, encLen, keyLength, publicKey, secretKey, modulus, &textLen, (unsigned char**) &text, public);

    if(success)
    {
        char* extension = Extension(whichFile);
        if(!strcmp(extension,TEXT_EXTENSION))
            SaveToFile((unsigned char*) text, textLen, textFilePath, 0, 0);
        else if(!strcmp(extension, AES_KEY_EXTENSION))
        {
            int separatorSize =  strlen(keyIvSeparator);
            char* aesFilePath = DefinePath(KEY_LOCATION, textFile, AES_KEY_EXTENSION);
            char* tempPtr = strstr(text, keyIvSeparator);

            int tempKeyLength = (tempPtr - text) * BYTE;
            int tempBlockLength = strlen(tempPtr + separatorSize) * BYTE;
            if(tempKeyLength != 128 && tempKeyLength != 192 && tempKeyLength != 256)
                return false;
            unsigned char* tempKeys[2];
            char* aesKeyLengths[2];
            int numOfCharsKey = tempKeyLength/BYTE;
            int numOfCharsIV = tempBlockLength/BYTE;
            tempKeys[0] = CharToHex((unsigned char*) text, &numOfCharsKey);
            tempKeys[1] = CharToHex((unsigned char*) (tempPtr + separatorSize), &numOfCharsIV);
            aesKeyLengths[0]= IntToHex(tempKeyLength);
            aesKeyLengths[1] = IntToHex(tempBlockLength);

            PrepareAndSave(AES_KEY, tempKeys, NULL, aesKeyLengths,  NULL, aesFilePath);
            free(aesFilePath);
        }
        free(extension); 
        if(print == 1)
        {
            printf("\nRSA keys: \n");
            printf("Modulus: \n%s\n", modulus);
            if(public)
                printf("Public exponent: \n%s\n", publicKey);
            else
                printf("Private exponent: \n%s\n", secretKey);
            printf("Encrypted text: \n%s\n", encText);
            printf("Clear text: \n%s\n", text);
        }
    }  
    free(text);
    free(encText);
    free(keyLengths);
    free(textFilePath);
    free(rsaKeyPath);
    free(encFilePath);
    free(keys);
    return true;
}

bool RSADecryption(unsigned char *cipherText, int encLen, int keyLength, char *publicKey, char *secretKey, char *modulus, int *plainTextLen, unsigned char **plainText, char public)
{
    *plainTextLen = 0;
    encLen = keyLength/BYTE;
    
    unsigned char *encrypted = calloc(encLen + 1, sizeof(unsigned char));
    unsigned char *decrypted = calloc(encLen + 1, sizeof(unsigned char));

    EVP_PKEY* pkey = (!public) ? RSA_fromBase64Private(modulus, secretKey, publicKey) : RSA_fromBase64Public(modulus, publicKey);
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);

    bool success = Base64Decode((char*) cipherText, &encrypted);
    if(!success)
    {
        ErrorHandler(RSADECODING, NULL);
        return false;
    }

    *plainTextLen = (!public) ? RSA_private_decrypt(encLen, encrypted, decrypted, rsa, RSA_PKCS1_PADDING) :
                                RSA_public_decrypt(encLen, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);

    *plainText = decrypted;

    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    free(encrypted);
    return true;
}

bool GUISHADigest(char* textFile, char* digestFile, unsigned char** digest, int* digestLen, char whichFunction, char print)
{
    char* textFilePath = DefinePath(FILE_LOCATION, textFile, TEXT_EXTENSION);
    char* digestFilePath = DefinePath(ENCRYPTED_LOCATION, digestFile, SHA_DIGEST_EXTENSION);

    char* text = NULL;
    unsigned char* tempDigest = NULL;
    int tempDigestLen = 0;

    int textLen = ReadFile(textFilePath, (unsigned char**)&text, 0);
    if(textLen == 0)
        return false;

    if(print == 1)
        printf("\nClear text:\n%s\n", text);

    bool success = (whichFunction == 0) ? SHADigest(text, textLen, &tempDigest, &tempDigestLen) : SHA2Digest(text, textLen, &tempDigest, &tempDigestLen);
    if(success)
    {
        tempDigest = CharToHex(tempDigest, &tempDigestLen);
        tempDigestLen = strlen((char*) *digest);
    
        unsigned char* data[1];
        data[0] = tempDigest;
        PrepareAndSave(SHA_DIGEST, NULL, data, NULL, textFilePath, digestFilePath);

        if(digest != NULL && digestLen != NULL)
        {
            *digest = tempDigest;
            *digestLen = tempDigestLen;
        }
        return true;
    }
    return false;
}

bool SHADigest(const char *message, int messageLen, unsigned char **digest, int *digestLen)
{
    EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
    {
        ErrorHandler(EVPLIBRARY, NULL);
        return false;
    }

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL))
	{
        ErrorHandler(SHAINIT, NULL);
        return false;
    }

	if(1 != EVP_DigestUpdate(mdctx, message, messageLen * sizeof(const char)))
	{
        ErrorHandler(SHACALC, NULL);
        return false;
    }

	if((*digest = OPENSSL_malloc(EVP_MD_size(EVP_sha512()))) == NULL)
	{
        ErrorHandler(SHAALLOC, NULL);
        return false;
    }

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, (unsigned int*)digestLen))
	{
        ErrorHandler(SHACALC, NULL);
        return false;
    }

	EVP_MD_CTX_destroy(mdctx);

    return true;
}

bool SHA2Digest(const char *message, int messageLen, unsigned char **digest, int *digestLen)
{
    unsigned char*  hash = calloc(33, sizeof(unsigned char*));
    MSHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char*) message, messageLen);
    sha256_final(&ctx,hash);
    *digestLen = 32;
    *digest = hash;
    return true;
}

bool GUISignature(char* inputFile, char* keyFile, char* signatureFile, char print)
{
    char* inputFilePath = DefinePath(FILE_LOCATION, inputFile, TEXT_EXTENSION);
    char* keyFilePath = DefinePath(KEY_LOCATION, keyFile, RSA_SECRET_KEY_EXTENSION);
    char* signatureFilePath = DefinePath(ENCRYPTED_LOCATION, signatureFile, SIGNATURE_EXTENSION);

    int keyLength;
    int textLen;
    int encLen;
    unsigned char* encText;
    char* publicKey;
    char* secretKey;
    char* modulus;
    char* text;
    unsigned char* signature;
    int signatureLength;
    unsigned char** keys = NULL;
    char** keyLengths = NULL;

    textLen = ReadFile(inputFilePath, (unsigned char**) &text, 0);
    if(textLen == 0)
        return false;

    bool success = ReadAndPrepare(RSA_SECRET_KEY, keyFilePath, &keys, NULL, &keyLengths);
    if(!success || *keys == NULL || *keyLengths == NULL)
        return false;
    
    keyLength = HexToInt(*keyLengths);
    modulus = (char*) *keys;
    publicKey = (char*) *(keys + 1);
    secretKey = (char*) *(keys + 2);

    success = Signature(text, keyLength, modulus, publicKey, secretKey, &signature, &signatureLength);
    if(!success)
        return false;

    unsigned char* data[1];
    data[0] = signature;
    char *tempKeyLengths[2];
    tempKeyLengths[0] = IntToHex(512);
    tempKeyLengths[1] = *keyLengths;

    PrepareAndSave(SIGNATURE_TYPE, NULL, data, tempKeyLengths, inputFilePath, signatureFilePath);

    if(print == 1)
    {
        printf("Clear text: \n%s\n", text);
        printf("\nRSA key: \n");
        printf("Modulus: \n%s\n", modulus);
        printf("Private exponent: \n%s\n", secretKey);
        printf("Encrypted text: \n%s\n", signature);
    }
    return true;
}  

bool Signature(char* plainText, int keyLength, char* modulus, char* publicKey, char* secretKey, unsigned char** signature, int* signatureLength)
{
    char* digest;
    int digestLen;
    unsigned char* encText;
    int encLen;
    bool success = SHADigest(plainText, strlen(plainText),(unsigned char**) &digest, &digestLen);
    if(!success)
        return false;

    success = RSAEncryption(digest, digestLen, keyLength, publicKey, secretKey, modulus, &encLen, &encText, 1);
    if(!success)
        return false;
    
    *signature = encText;
    *signatureLength = encLen;
    return true;
}

bool GUICheckSignature(char* inputFile, char* signatureFile, char* keyFile, bool* valid, char print)
{
    char* inputFilePath = DefinePath(FILE_LOCATION, inputFile, TEXT_EXTENSION);
    char* keyFilePath = DefinePath(KEY_LOCATION, keyFile, RSA_PUBLIC_KEY_EXTENSION);
    char* signatureFilePath = DefinePath(ENCRYPTED_LOCATION, signatureFile, SIGNATURE_EXTENSION);

    int keyLength;
    int textLen;
    int decryptedLen;
    char* publicKey;
    char* secretKey;
    char* modulus;
    char* text;
    char* decrypted;
    unsigned char** data;
    unsigned char* signature;
    int signatureLength;
    unsigned char** keys = NULL;
    char** keyLengths = NULL;
    char** secondKeyLengths = NULL;

    textLen = ReadFile(inputFilePath, (unsigned char**) &text, 0);
    if(textLen == 0)
        return false;

    bool success = ReadAndPrepare(RSA_PUBLIC_KEY, keyFilePath, &keys, NULL, &keyLengths);
    if(!success || *keys == NULL || *keyLengths == NULL)
        return false;
    
    keyLength = HexToInt(*keyLengths);
    modulus = (char*) *keys;
    publicKey = (char*) *(keys + 1);

    success = ReadAndPrepare(SIGNATURE_TYPE, signatureFilePath, NULL, &data, &secondKeyLengths);
    signature = *data;

    success = CheckSignature(text, signature, strlen((char*) signature), keyLength, publicKey, modulus, valid, &decrypted, &decryptedLen);
    if(!success)
        return false;

    if(print == 1)
    {
        printf("Encrypted text: \n%s\n", signature);
        printf("\nRSA key: \n");
        printf("Modulus: \n%s\n", modulus);
        printf("Public exponent: \n%s\n", publicKey);
        printf("Clear text: \n%s\n", text);
        printf("Decrypted text: \n%s\n", decrypted);
    }
    return true;
}

bool CheckSignature(char* text, unsigned char* signature, int signatureLength, int keyLength, char* publicKey, char* modulus, bool* valid, char** decrypted, int* decryptedLen)
{

    unsigned char* digest;
    int digestLen;
    bool success = RSADecryption(signature, signatureLength, keyLength, publicKey, NULL, modulus, &digestLen, &digest, 1);
    if(!success)
        return false;

    unsigned char* realDigest;
    int realDigestLen;
    success = SHADigest(text, strlen(text), &realDigest, &realDigestLen);
    if(!success)
        return false;
    if(digestLen != realDigestLen)
        *valid = false;
    if(!strcmp((char*) digest, (char*) realDigest))
        *valid = true;
    else
        *valid = false;

    *decrypted = (char*) digest;
    *decryptedLen = digestLen;
    return true;
}

bool GUIEnvelope(char* inputFile, char* keyFile, char* envelopeFile, char print)
{
    char* inputFilePath = DefinePath(FILE_LOCATION, inputFile, TEXT_EXTENSION);
    char* keyFilePath = DefinePath(KEY_LOCATION, keyFile, RSA_PUBLIC_KEY_EXTENSION);
    char* envelopeFilePath = DefinePath(ENCRYPTED_LOCATION, envelopeFile, ENVELOPE_EXTENSION);

    int keyLength;
    int textLen;
    char* publicKey;
    char* modulus;
    char* text;
    unsigned char* envelopeData;
    int envelopeDataLen;
    unsigned char* envelopeCryptKey;
    int envelopeCryptKeyLen;
    unsigned char** keys = NULL;
    char** keyLengths = NULL;

    textLen = ReadFile(inputFilePath, (unsigned char**) &text, 0);
    if(textLen == 0)
        return false;

    bool success = ReadAndPrepare(RSA_PUBLIC_KEY, keyFilePath, &keys, NULL, &keyLengths);
    if(!success || *keys == NULL || *keyLengths == NULL)
        return false;
    
    keyLength = HexToInt(*keyLengths);
    modulus = (char*) *keys;
    publicKey = (char*) *(keys + 1);

    success = Envelope(text, keyLength, modulus, publicKey, &envelopeData, &envelopeDataLen, &envelopeCryptKey, &envelopeCryptKeyLen);
    if(!success)
        return false;

    unsigned char* key[1];
    key[0] = envelopeCryptKey;
    unsigned char* data[1];
    data[0] = envelopeData;
    char *tempKeyLengths[2];
    tempKeyLengths[0] = IntToHex(128);
    tempKeyLengths[1] = *keyLengths;

    PrepareAndSave(ENVELOPE, key, data, tempKeyLengths, inputFilePath, envelopeFilePath);

    if(print == 1)
    {
        printf("Clear text: \n%s\n", text);
        printf("\nRSA key: \n");
        printf("Modulus: \n%s\n", modulus);
        printf("Public exponent: \n%s\n", publicKey);
        printf("Encrypted text: \n%s\n", envelopeData);
        printf("Encrypted key: \n%s\n", envelopeCryptKey);

    }
    return true;
}  

bool Envelope(char* plainText, int keyLength, char* modulus, char* publicKey, unsigned char** envelopeData, int* envelopeDataLen, unsigned char** envelopeCryptKey, int* envelopeCryptKeyLen)
{
    int textLen = strlen(plainText);
    unsigned char* aesKey;
    unsigned char* iv;
    unsigned char* encText = (unsigned char*) calloc(3 * textLen, sizeof(unsigned char));
    int encLen;
    unsigned char *encKey = calloc(keyLength/BYTE + 1, sizeof(unsigned char));
    int encKeyLen;

    bool success =  GenerateAESKey(envelopeAesKeyLength, envelopeBlockLength, &aesKey, &iv);
    if(!success)
        return false;
    
    encLen = AESEncryption(plainText, textLen, aesKey, envelopeAesKeyLength, iv, &encText);
    if(encLen == 0)
        return false;
    
    textLen = strlen(aesKey) + strlen(iv) + strlen(keyIvSeparator);
    unsigned char* text = (unsigned char*) calloc(textLen + 1 , sizeof(unsigned char*));
    strncpy((char*) text, (char*) aesKey, strlen(aesKey));
    strncat((char*) text, keyIvSeparator, strlen(keyIvSeparator));
    strncat((char*) text, (char*) iv, strlen(iv));

    int textSize = strlen((char*) text);
    success = RSAEncryption((char*) text, textSize, keyLength, publicKey, NULL, modulus, &encKeyLen, &encKey, 0);
    if(!success)
        return false;
    
    *envelopeData = encText;
    *envelopeDataLen = encLen;
    *envelopeCryptKey = encKey;
    *envelopeCryptKeyLen = encKeyLen;
    return true;
}

bool GUIOpenEnvelope(char* envelopeFile, char* keyFile, char* outputFile, char print)
{
    char* outputFilePath = DefinePath(DECRYPTED_LOCATION, outputFile, TEXT_EXTENSION);
    char* keyFilePath = DefinePath(KEY_LOCATION, keyFile, RSA_SECRET_KEY_EXTENSION);
    char* envelopeFilePath = DefinePath(ENCRYPTED_LOCATION, envelopeFile, ENVELOPE_EXTENSION);

    int keyLength;
    int textLen;
    char* publicKey;
    char* secretKey;
    char* modulus;
    char* text;
    unsigned char* envelopeData;
    unsigned char* envelopeCryptKey;
    unsigned char** data = NULL;
    unsigned char** keys = NULL;
    unsigned char** rsaKeys = NULL;
    char** rsaKeyLengths = NULL;
    char** keyLengths = NULL;

    bool success = ReadAndPrepare(ENVELOPE, envelopeFilePath, &keys, &data, &keyLengths);
    if(!success || *keys == NULL || *keyLengths == NULL)
        return false;

    envelopeData = *data;
    envelopeCryptKey = *keys;

    success = ReadAndPrepare(RSA_SECRET_KEY, keyFilePath, &rsaKeys, NULL, &rsaKeyLengths);
    if(!success || *rsaKeys == NULL || *rsaKeyLengths == NULL)
        return false;
    
    keyLength = HexToInt(*rsaKeyLengths);
    modulus = (char*) *rsaKeys;
    publicKey = (char*) *(rsaKeys + 1);
    secretKey = (char*) *(rsaKeys + 2);

    success = OpenEnvelope(envelopeData, keyLength, publicKey, secretKey, modulus, envelopeCryptKey, &text, &textLen);
    if(!success)
        return false;
    
    SaveToFile((unsigned char*) text, textLen, outputFilePath, 0, 0);


    if(print == 1)
    {
        printf("Encrypted text: \n%s\n", envelopeData);
        printf("Encrypted key: \n%s\n", envelopeCryptKey);
        printf("\nRSA key: \n");
        printf("Modulus: \n%s\n", modulus);
        printf("Secret exponent: \n%s\n", secretKey);
        printf("Clear text: \n%s\n", text);
    }
    return true;
}  

bool OpenEnvelope(unsigned char* envelopeData, int keyLength, char* publicKey, char* secretKey, char* modulus, unsigned char* envelopeCryptKey, char** text, int* textLength)
{

    char* plainText = (char*) calloc(keyLength/BYTE + 1, sizeof(char));;
    int textLen;
    unsigned char* aesKey;
    unsigned char* iv;
    bool success = RSADecryption(envelopeCryptKey, strlen((char*) envelopeCryptKey), keyLength, publicKey, secretKey, modulus, &textLen, (unsigned char**) &plainText, 0);
    if(!success)
        return false;

    int separatorSize =  strlen(keyIvSeparator);
    char* tempPtr = strstr(plainText, keyIvSeparator);

    int tempKeyLength = (tempPtr - plainText) * BYTE;
    int tempBlockLength = strlen(tempPtr + separatorSize) * BYTE;
    if(tempKeyLength != envelopeAesKeyLength)
        return false;
    char* aesKeyLengths[2];
    int numOfCharsKey = tempKeyLength/BYTE;
    int numOfCharsIV = tempBlockLength/BYTE;
    aesKey = CharToHex((unsigned char*) text, &numOfCharsKey);
    iv = CharToHex((unsigned char*) (tempPtr + separatorSize), &numOfCharsIV);
    
    free(plainText);
    plainText = (char*) calloc(strlen((char*) envelopeData), sizeof(char));

    textLen = AESDecryption(envelopeData, strlen((char*) envelopeData), aesKey, envelopeAesKeyLength, iv, &plainText);
    if(textLen == 0)
        return false;
    
    *text = plainText;
    *textLength = textLen;
    return true;
}
