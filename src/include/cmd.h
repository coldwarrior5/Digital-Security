#ifndef CMD_H_
#define CMD_H_

enum FileTypes
{
    AES_KEY,
    AES_ENCRYPTION,
    RSA_PUBLIC_KEY,
    RSA_SECRET_KEY,
    RSA_ENCRYPTION,
    SHA_DIGEST,
    ENVELOPE,
    SIGNATURE_TYPE,
    SEAL
};

extern const char* const FileTypeMethods[9];
extern const char* const FileTypeDescription[9];

enum ParseTypes
{
    COMMENT,
    EMPTY_LINE,
    BEGIN_CRYPTO,
    END_CRYPTO,
    KEY,
    VALUE
};

extern enum ParseTypes ParseType;
extern bool terminated;

int CommandMode();
int ChoiceLoop();
int ActionChoice(const char *selection, int size);
int UserChoice(int size);
void PrepareAndSave(enum FileTypes fileType, unsigned char** key, unsigned char** data, char** keyLengths, const char* const sourceFile, const char* const destinationFile);
char** AssignMethod(enum FileTypes fileType);
int PrepareToSave(unsigned char** buffer, const char* const  description, const char* const fileName, char** method, int methodSize, char** keyLengths, int keySize, unsigned char* secretKey, unsigned char* iv, unsigned char* modulus, unsigned char* pe, unsigned char* se, unsigned char* sign, unsigned char* data, unsigned char* envpData, unsigned char* envpCryptKey);
void AddKeyValuePair(char** buffer, const char* key, unsigned char** values, int valueSize);
bool ReadAndPrepare(enum FileTypes fileType, const char* fileName, unsigned char*** keys, unsigned char*** data, char*** keyLengths);
bool ParseFile(enum FileTypes fileType, const char* fileName, char*** keyLengths, unsigned char*** keys, unsigned char*** iv, unsigned char*** modulus, unsigned char*** pe, unsigned char*** se, unsigned char*** sign, unsigned char*** data, unsigned char*** envpData, unsigned char*** envpCryptKey, unsigned char*** encFilePath);
bool CheckMethods(char* method, enum FileTypes fileType);
enum ParseTypes ParseLine(unsigned char* line, unsigned char** output);
unsigned char* StrTok(unsigned char* text, char delim);

#endif