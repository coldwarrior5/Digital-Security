#include "allInclusions.h"

bool Base64Encode(unsigned char* message, int messageLen, char** buffer) 
{
    BIO *bio, *b64;
    BUF_MEM *ptr;
    int encodedLen = 4 * ceil((double)messageLen / 3);
    int carriageReturn = ceil((float)encodedLen / 64);
    encodedLen += carriageReturn;
    *buffer = (char *)calloc(encodedLen + 1, sizeof(char));

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, message, messageLen);       
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &ptr);
    int len = ptr->length;
    if(len != encodedLen)
    {
        ErrorHandler(B64DECODE, NULL);
        return false;
    }
    memcpy(*buffer, ptr->data, encodedLen);
    (*buffer)[encodedLen] = '\0';
    
    BIO_free_all(bio);

    return true;
}

bool Base64Decode(char* b64message, unsigned char** buffer)
{
    BIO *bio, *b64;
    int decodeLen = CalcDecodeLength(b64message);
    int len = 0;
    *buffer = (unsigned char*)calloc(decodeLen + 1, sizeof(unsigned char));

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(b64message, strlen(b64message));
    bio = BIO_push(b64, bio);
    len = BIO_read(bio, *buffer, strlen(b64message));
    if(len != decodeLen)
    {
        ErrorHandler(B64DECODE, NULL);
        return false;
    }

    (*buffer)[len] = '\0';

    BIO_free_all(bio);

    return true; //success
}

//Calculates the length of a decoded base64 string
int CalcDecodeLength(const char* b64input)
{
    int len = strlen(b64input);
    int padding = 0;
    int carriageReturn = ceil((float)len / 65);

    if (b64input[len-2] == '=' && b64input[len-3] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-2] == '=') //last char is =
        padding = 1;

    len -= padding;
    len -= carriageReturn;
    return (int)len*0.75;
}

// Character as two hex numbers
unsigned char* CharToHex(unsigned char *input, int *length)
{
    int roundoff = 64;
    int offset = 0;
    int tempLength = *length;
    *length *= 2;
    *length += 1;
    int overflow = (tempLength/2 - 1)/roundoff;
    overflow = (overflow < 0) ? 0 : overflow;
    *length += overflow;

    unsigned char* pointer = input;

    unsigned char *buffer = (unsigned char *)malloc(*length * sizeof(unsigned char));
    memset(buffer, 0, *length);

    if (NULL == pointer)
        return NULL;
    else
    {
	int i;
        for(i = 0; i < tempLength; i++)
        {
            if((i*2)%roundoff == 0 && i != 0)
            {
                sprintf((char*)buffer + i*2 + offset, "%s", "\n");
                offset++;
            }
            sprintf((char*)buffer + i*2 + offset, "%02X", *(pointer + i));
        }
    }
    return buffer;
}

// Hex representation back to char representation
unsigned char* HexToChar(unsigned char *input, int length)
{
    int offset = 0;
    unsigned char* pointer = input;
    unsigned char *buffer = (unsigned char *)calloc(length/2 + 1, sizeof(unsigned char));

    if (NULL == pointer)
        return NULL;
    else
    {
	unsigned char *p;
        for (p = StrTok(pointer, '\n'); p != NULL; p = StrTok(NULL, '\n'))
        {
            int len = FieldSize(p);
	    unsigned i;
            for (i = 0; i < len; i+=2)
            {
                sscanf((char*)(p + i + offset), "%2x", &uchr);
                buffer[(i + offset)/2] = uchr;
            }
             offset += len;
        }
    }
    buffer[length/2] = '\0';
    return buffer;
}

int CharToInt(char* number) // Has to be char
{
    char *endptr;
    int result = -1;

	long lResult = strtol(number, &endptr, BASE);
    
    if(endptr == number || ((lResult <= INT_MIN || lResult >= INT_MAX) && errno == ERANGE))
        result = -1;
    else
        result = (int) lResult;

    return result;
}

// Int represented as ascii characters
char* IntToChar(int number, int* length)
{
    char* buffer = malloc(sizeof(char)*10); // Has to be char
    memset(buffer, 0, 10);
    snprintf(buffer, 10, "%d", number);
    int i;
    for(i = 0; i < 10; i++)
    {
        if(*(buffer + i) == 0)
        {
            *length = i;
            break;
        }
    }
    return buffer;
}

// Conversion from dec to hex
char* IntToHex(int number)
{
    char *buffer = (char *)malloc(10 * sizeof(char));   // Has to be char
    memset(buffer, 0, 10);

    sprintf((char*)buffer, "%x", number);

    return buffer;
}

// Conversion from hex to dec
int HexToInt(char* hexNumber)   // Has to be char
{
    int number;

    sscanf(hexNumber, "%x", &number);
    
    return number;
}

BIGNUM* bignum_base64_decode(const char* base64bignum) 
{
    BIGNUM* bn = NULL;
    bn = BN_new();
    unsigned char* data;
    int success = Base64Decode((char*) base64bignum, &data);
    if(!success)
    {
        ErrorHandler(B64DECODE, NULL);
        return NULL;
    }
    int len = strlen((char*) data);
    if (len) {
        len = BN_dec2bn(&bn,(const char*) data);
    }
    free(data);
    return bn;
}

unsigned char* bignum_base64_encode(const BIGNUM* base64bignum) 
{
   unsigned char* data;
   unsigned char* temp = NULL;
   data = (unsigned char*) BN_bn2dec(base64bignum);
   bool success = Base64Encode(data, strlen((char*) data), (char**) &temp);
   if(!success)
   {
       ErrorHandler(B64ENCODE, NULL);
       return NULL;
   }

   data = temp;
   return data;
}

EVP_PKEY* RSA_fromBase64Public(const char* modulus_b64, const char* publicExponent) 
{
   BIGNUM *n = bignum_base64_decode(modulus_b64);
   BIGNUM *e = bignum_base64_decode(publicExponent);

   if (!n) printf("Invalid encoding for modulus\n");
   if (!e) printf("Invalid encoding for public exponent\n");

   if (e && n) {
       EVP_PKEY* pRsaKey = EVP_PKEY_new();
       RSA* rsa = RSA_new();
       rsa->e = e;
       rsa->n = n;
       EVP_PKEY_assign_RSA(pRsaKey, rsa);
       return pRsaKey;
   } else {
       if (n) BN_free(n);
       if (e) BN_free(e);
       return NULL;
   }
}

EVP_PKEY* RSA_fromBase64Private(const char* modulus_b64, const char* privateExponent, const char* publicExponent) 
{
    BIGNUM *n = bignum_base64_decode(modulus_b64);
    BIGNUM *d = bignum_base64_decode(privateExponent);
    BIGNUM *e = bignum_base64_decode(publicExponent);

    if (!n) printf("Invalid encoding for modulus\n");
    if (!d) printf("Invalid encoding for private exponent\n");
    if (!e) printf("Invalid encoding for public exponent\n");

    if (d && n && e)
    {
        EVP_PKEY* pRsaKey = EVP_PKEY_new();
        RSA* rsa = RSA_new();
        rsa->d = d;
        rsa->n = n;
        rsa->e = e;
        EVP_PKEY_assign_RSA(pRsaKey, rsa);
        return pRsaKey;
    } 
    else {
        if (n) BN_free(n);
        if (d) BN_free(d);
        if (e) BN_free(e);
        return NULL;
    }
}
