#include "allInclusions.h"

const char *mainSelection = "\n1) AES\n2) RSA\n3) SHA\n4) Envelope\n5) Signature\n6) Seal\n7) Display key\n8) Display text\n9) Display encrypted text\n";
const char *aesSelection  = "\n1) Generate key\n2) Encrypt\n3) Decrypt\n";
const char *rsaSelection  = "\n1) Generate key pairs\n2) Encrypt\n3) Decrypt\n";;
const char *envpSelection = "\n1) Generate envelope\n2) Open envelope\n";
const char *signSelection = "\n1) Generate signature\n2) Check the signature\n";
const char *sealSelection = "\n1) Generate seal\n2) Open sealed file\n";
const char *aesKeySize    = "\n1) 128\n2) 192\n3) 256\n";
const char *aesBlockSize  = "\n1) 128\n";
const char *rsaKeySize    = "\n1) 1024\n2) 2048\n3) 3072\n";

const char *bigSeparator = "\n_________________\n\n";
const char *smallSeparator = "\n\n";
const char *valuePadding = "    ";
bool terminated = false;
const int fileSize = 30;
unsigned char* strokPointer;

const char* const FileTypeMethods[9] = {"AES", "AES", "RSA", "RSA", "RSA", "SHA", "AES,RSA", "SHA,RSA", "AES,SHA,RSA"};
const char* const FileTypeDescription[9] = {"Secret key", "Crypted file", "Public key", "Private key", "Crypted file", "SHA digest", "Envelope", "Signature", "Seal"};

int CommandMode()
{
    printf("Digital security");
    printf("%s", bigSeparator);
    return ChoiceLoop();
}

int ChoiceLoop()
{
    int actionId = -1;
    int subActionId = 1;
    int returnValue = 0;

    char inFile[fileSize];
    char outFile[fileSize];
    char keyFile[fileSize];
    char secondKeyFile[fileSize];

    bool valid;

    while(!terminated)
    {
        actionId = ActionChoice(mainSelection, 9);
        if(terminated) break;
        switch(actionId)
        {
            case 1:
                subActionId = ActionChoice(aesSelection, 3);
                break;
            case 2:
                subActionId = ActionChoice(rsaSelection, 3);
                break;
            case 3:
                break;
            case 4:
                subActionId = ActionChoice(envpSelection, 2);
                break;
            case 5:
                subActionId = ActionChoice(signSelection, 2);
                break;
            case 6:
                subActionId = ActionChoice(sealSelection, 2);
                break;
            case 7:
                break;
            case 8:
                break;
            case 9:
                break;
            default:
                printf("\nIncorrect choice\n");
                break;
        }

        if(terminated) continue;

        if((actionId == 1 || actionId == 2) && subActionId == 1)    // Generate keys
        {
            int keyLength = 0;
            int blockLength = 0;
            char fileName[80];
            printf("\nDefine key size\n");

            if(actionId == 1)
            {
                int keyChoice = ActionChoice(aesKeySize, 3);
                if(terminated) continue;
                keyLength = (keyChoice == 2)? 192 : 128;
                keyLength = (keyChoice == 3)? 256 : keyLength;

                printf("\nDefine block size\n");
                int blockChoice = ActionChoice(aesKeySize, 3);
                if(terminated) continue;
                blockLength = (blockChoice == 2)? 192 : 128;
                blockLength = (blockChoice == 3)? 256 : blockLength;

                printf("\nDefine key file name\n");
                scanf("%s", fileName);
                
                // Generate AES key
                unsigned char* key = GUIGenerateAESKey((int) keyLength, (int) blockLength, fileName);
                HexPrint(key, keyLength/BYTE);
            }
            else
            {
                int keyChoice = ActionChoice(rsaKeySize, 3);
                if(terminated) continue;
                keyLength = (keyChoice == 2)? 2048 : 1024;
                keyLength = (keyChoice == 3)? 3072 : keyLength;

                printf("\nDefine both public and secret key file name\n");
                scanf("%s", fileName);
                
                // GENERATE RSA key
                GUIGenerateRSAKeys(keyLength, fileName, 1);
            }
        }
        if(((actionId == 1 || actionId == 2) && subActionId == 2) || ((actionId == 4 || actionId == 5 || actionId == 6) && subActionId == 1))    // Encrypt
        {
            if(actionId == 2)   // RSA
            {
                printf("Define input file that will be encrypted, located in both folder %s or folder %s: ", FILE_LOCATION, KEY_LOCATION);
                scanf("%s", inFile);
            }
            else
            {
                printf("Define input file that will be encrypted, located in folder %s: ", FILE_LOCATION);
                scanf("%s", inFile);
            }

            if(actionId == 1)   // AES algorithm
            {
                printf("Define key file needed for encryption, located in folder %s: ", KEY_LOCATION);
                scanf("%s", keyFile);
            }
            else if(actionId == 2 || actionId == 4 || actionId == 6) // RSA or Envelope or Seal
            {
                printf("Define public key file of receiver needed for encryption, located in folder %s: ", KEY_LOCATION);
                scanf("%s", keyFile);
            }
            else
            {
                printf("Define secret key file of sender needed for encryption, located in folder %s: ", KEY_LOCATION);
                scanf("%s", keyFile);
            }

            if(actionId == 6)
            {
                printf("Define secret key file of sender needed for encryption, located in folder %s: ", KEY_LOCATION);
                scanf("%s", keyFile);
            }
                
            printf("Define name for encrypted file, it will be stored in folder %s: ", ENCRYPTED_LOCATION);
            scanf("%s", outFile);

            // This bit helps with trailing \n
            char input[5];
            fgets(input, 5, stdin);

            switch(actionId)
            {
                case 1:
                    GUIAESEncryption(keyFile, inFile, outFile, 0);
                    break;
                case 2:
                    GUIRSAEncryption(keyFile, inFile, outFile, 0, 0);
                    break;
                case 4:

                    break;
                case 5:
                    GUISignature(inFile, keyFile, outFile, 0);
                    break;
                case 6:
                    break;
            }
        }
        else if(((actionId == 1 || actionId == 2) && subActionId == 3) || ((actionId == 4 || actionId == 5 || actionId == 6) && subActionId == 2))   // Decrypt
        {
            printf("Define input file that will be decrypted, located in folder %s: ", ENCRYPTED_LOCATION);
            scanf("%s", inFile);

            if(actionId == 1)   // AES algorithm
            {
                printf("Define key file needed for decryption, located in folder %s: ", KEY_LOCATION);
                scanf("%s", keyFile);
            }
            else if(actionId == 2 || actionId == 4 || actionId == 6) // RSA or Envelope or Seal
            {
                printf("Define secret key file of receiver needed for decryption, located in folder %s: ", KEY_LOCATION);
                scanf("%s", keyFile);
            }
            else        // Signature
            {
                printf("Define public key file of sender needed for decryption, located in folder %s: ", KEY_LOCATION);
                scanf("%s", keyFile);
            }
            if(actionId == 5)
            {
                printf("Define name of signature file, located in folder %s: ", ENCRYPTED_LOCATION);
                scanf("%s", outFile);
            }
            else
            {
                printf("Define name for decrypted file, it will be stored in folder %s: ", DECRYPTED_LOCATION);
                scanf("%s", outFile);
            }
            

            // This bit helps with trailing \n
            char input[5];
            fgets(input, 5, stdin);
            
            switch(actionId)
            {
                case 1:
                    GUIAESDecryption(keyFile, inFile, outFile, 0);
                    break;
                case 2:
                    GUIRSADecryption(keyFile, inFile, outFile, 0, 0);
                    break;
                case 4:
                    break;
                case 5:
                    GUICheckSignature(inFile, outFile, keyFile, &valid, 0);
                    if(valid)
                        printf("\nThe message is true.\n");
                    if(!valid)
                        printf("\nThe message was tampered.\n");
                    break;
                case 6:
                    break;
            }
        }
        else if(actionId == 3)  // Hash
        {
            unsigned char* digest = NULL;
            int digestLen = 0;
            printf("Define input file needed for hash function, located in folder %s: ", FILE_LOCATION);
            scanf("%s", inFile);
            printf("Define output file needed for hash function, located in folder %s: ", ENCRYPTED_LOCATION);
            scanf("%s", outFile);

            // This bit helps with trailing \n
            char input[5];
            fgets(input, 5, stdin);
            
            // Calculate SHA digest
            bool success = GUISHADigest(inFile, outFile, &digest, &digestLen, 0, 0);
            if(success)
            {
                printf("\nMessage digest: ");
                HexPrint(digest, digestLen);
            }
        }
        else if(actionId == 7)  // Print generated keys
        {
            printf("Which key to print, located in folder %s: ", KEY_LOCATION);
            scanf("%s", keyFile);
            PrintKeys(keyFile);
        }
        else if(actionId == 8)  // Print regular text files
        {
            printf("Which file to display, located in folders %s, %s: ", FILE_LOCATION, DECRYPTED_LOCATION);
            scanf("%s", keyFile);
            PrintFiles(keyFile, 0);
        }
        else if(actionId == 9)  // Print encrypted files
        {
            printf("Which file to display, located in folders %s: ", ENCRYPTED_LOCATION);
            scanf("%s", keyFile);
            PrintFiles(keyFile, 0);
        }
    }
    return returnValue;
}

int ActionChoice(const char *selection, int size)
{
    printf("%s", selection);
    return UserChoice(size);
}

int UserChoice(int size)
{
    char input[10];
    char *endptr;
    int result = -1;

    scanf("%s", input);
    CheckTermination(input);
	long lResult = strtol(input, &endptr, BASE);
    
    while (!terminated && (endptr == input || ((lResult > size || lResult <= 0) && errno == ERANGE))) 
    {
        printf("Incorrect choice, must be within 1 and %d\n", size);
        scanf("%s", input);
        CheckTermination(input);
        lResult = strtol(input, &endptr, BASE);
    }
    
    result = (int) lResult;
    return result;
}

void PrepareAndSave(enum FileTypes fileType, unsigned char** key, unsigned char** data, char** keyLengths, const char* const sourceFile, const char* const destinationFile)
{
    unsigned char* text = NULL;
    char** method = AssignMethod(fileType);
    
    int size = 0;

    switch(fileType)
    {
        case AES_KEY:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], NULL, method, 1, keyLengths, 2, *key, *(key + 1), NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            break;
        case AES_ENCRYPTION:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], sourceFile, method, 1, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, *data, NULL, NULL);
            break;
        case RSA_PUBLIC_KEY:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], NULL, method, 1, keyLengths, 1, NULL, NULL, *key, *(key + 1), NULL, NULL, NULL, NULL, NULL);
            break;
        case RSA_SECRET_KEY:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], NULL, method, 1, keyLengths, 1, NULL, NULL, *key, *(key + 1), *(key + 2), NULL, NULL, NULL, NULL);
            break;
        case RSA_ENCRYPTION:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], sourceFile, method, 1, keyLengths, 1,  NULL, NULL, NULL, NULL, NULL, NULL, *data, NULL, NULL);
            break;
        case SHA_DIGEST:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], sourceFile, method, 1, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, *data, NULL, NULL);
            break;
        case ENVELOPE:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], sourceFile, method, 2, keyLengths, 2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, *data, *key);
            break;
        case SIGNATURE_TYPE:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], sourceFile, method, 2, keyLengths, 2, NULL, NULL, NULL, NULL, NULL, *data, NULL, NULL, NULL);
            break;
        case SEAL:
            size = PrepareToSave(&text, FileTypeDescription[(int)fileType], sourceFile, method, 3, keyLengths, 3, NULL, NULL, NULL, NULL, NULL, *data, NULL, *(data + 1), *key);
            break;
    }
    SaveToFile(text, size, destinationFile, 0, 0);
    free(text);
    return;
}

char** AssignMethod(enum FileTypes fileType)
{
    char** methods = calloc(1, sizeof(char*));
    const char* const typeMethods = FileTypeMethods[(int)fileType];
    int i = 0;
    char*p = strchr(typeMethods, ',');
    char* lastPlace = (char*) typeMethods;
    do
    {
        methods = realloc(methods, (i+1) * sizeof(char*));
        int size = (p != NULL) ? p - lastPlace : strlen(lastPlace);
        *(methods + i) = (char*) calloc(size + 1, sizeof(char));
        strncpy(*(methods + i), lastPlace, size);
        if(p == NULL)
            break;
        i++;
        p++;
        lastPlace = p;
        p = strchr(lastPlace, ',');
    }while(p != NULL || strlen(lastPlace) > 0);

    return methods;
}

int PrepareToSave(unsigned char** buffer, const char* const description, const char* const fileName, char** method, int methodSize, char** keyLengths, int keyLengthSize, unsigned char* secretKey, unsigned char* iv, unsigned char* modulus, unsigned char* pe, unsigned char* se, unsigned char* sign, unsigned char* data, unsigned char* envpData, unsigned char* envpCryptKey)
{
    int len = 0;
    char* tempBuffer = (char*)malloc(sizeof(char)* MAX_FILE_SIZE);
    if(tempBuffer == NULL)
        ErrorHandler(MALLOC, "When creating an output file.");
    memset(tempBuffer, 0, MAX_FILE_SIZE);

    strcat(tempBuffer, BEGIN_FILE);        
    strcat(tempBuffer, "\n");

    AddKeyValuePair(&tempBuffer, DESCRIPTION, (unsigned char**) &description, 1);
    AddKeyValuePair(&tempBuffer, METHOD, (unsigned char**) method, methodSize);  
    if(fileName != NULL)
        AddKeyValuePair(&tempBuffer, FILE_NAME, (unsigned char**) &fileName, 1);
    if(keyLengthSize != 0)
        AddKeyValuePair(&tempBuffer, KEY_LENGTH, (unsigned char**) keyLengths, keyLengthSize);
    if(secretKey != NULL)
         AddKeyValuePair(&tempBuffer, SECRET_KEY, &secretKey, 1);
    if(iv != NULL)
        AddKeyValuePair(&tempBuffer, INITIALIZATION_VECTOR,  &iv, 1);
    if(modulus != NULL)
        AddKeyValuePair(&tempBuffer, MODULUS, &modulus, 1);
    if(pe != NULL)
        AddKeyValuePair(&tempBuffer, PUBLIC_EXPONENT, &pe, 1);
    if(se != NULL)
        AddKeyValuePair(&tempBuffer, PRIVATE_EXPONENT, &se, 1);
    if(sign != NULL)
        AddKeyValuePair(&tempBuffer, SIGNATURE, &sign, 1);
    if(data != NULL)
        AddKeyValuePair(&tempBuffer, DATA, &data, 1);
    if(envpData != NULL)
        AddKeyValuePair(&tempBuffer, ENVELOPE_DATA, &envpData, 1);
    if(envpCryptKey != NULL)
        AddKeyValuePair(&tempBuffer, ENVELOPE_CRYPT_KEY, &envpCryptKey, 1);

    strcat(tempBuffer, END_FILE);
    strcat(tempBuffer, "\n");

    *buffer = (unsigned char*)tempBuffer;

    while(*(tempBuffer + len) != 0)
        len++;

    return len;
}

void AddKeyValuePair(char** buffer, const char* key, unsigned char** values, int valueSize)
{
    strcat(*buffer, key);
    strcat(*buffer, "\n");
    strcat(*buffer, valuePadding);
    for(int i = 0; i < valueSize; i++)
    {
        int iter = 0;
        for (unsigned char *p = StrTok(*(values + i), '\n'); p != NULL; p = StrTok(NULL, '\n'))
        {
            if(iter != 0)
            {
                strcat(*buffer, "\n");
                strcat(*buffer, valuePadding);
            }
            strcat(*buffer, (char*) p);
            iter++;
        }

        if(i != valueSize - 1)
        {
            strcat(*buffer, "\n");
            strcat(*buffer, valuePadding);
        }
    }
    strcat(*buffer, smallSeparator);
}

bool ReadAndPrepare(enum FileTypes fileType, const char* fileName, unsigned char*** keys, unsigned char*** data, char*** keyLengths)
{
    char **tempKeyLengths = NULL;
    unsigned char **iv = NULL; 
    unsigned char **tempKeys = NULL;
    unsigned char **modulus = NULL;
    unsigned char **pe = NULL;
    unsigned char **se = NULL;
    unsigned char **sign = NULL;
    unsigned char **tempData = NULL;
    unsigned char **envpData = NULL;
    unsigned char **envpCryptKey = NULL;
    unsigned char **encFilePath = NULL;

    bool success = ParseFile(fileType, fileName, keyLengths, &tempKeys, &iv, &modulus, &pe, &se, &sign, &tempData, &envpData, &envpCryptKey, &encFilePath);
    
    if(!success)
        return success;
    
    switch(fileType)
    {
        case AES_KEY:
            *keys = malloc(2 * sizeof(unsigned char*));
            **keys = *tempKeys;
            *(*keys + 1) = *iv;
            break;
        case AES_ENCRYPTION:
            *data = malloc(sizeof(unsigned char*));
            **data = *tempData;
            break;
        case RSA_PUBLIC_KEY:
            *keys = malloc(2 * sizeof(unsigned char*));
            **keys = *modulus;
            *(*keys + 1) = *pe;
            break;
        case RSA_SECRET_KEY:
            *keys = malloc(3 * sizeof(unsigned char*));
            **keys = *modulus;
            *(*keys + 1) = *pe;
            *(*keys + 2) = *se;
            break;
        case RSA_ENCRYPTION:
            *data = malloc(2 * sizeof(unsigned char*));
            **data = *tempData;
            *(*data + 1) = *encFilePath;
            break;
        case SHA_DIGEST:
            *data = malloc(sizeof(unsigned char*));
            **data = *tempData;
            break;
        case ENVELOPE:
            *data = malloc(sizeof(unsigned char*));
            **data = *envpData;
            *keys = malloc(sizeof(unsigned char*));
            **keys = *envpCryptKey;
            break;
        case SIGNATURE_TYPE:
            *data = malloc(sizeof(unsigned char*));
            **data = *sign;
            break;
        case SEAL:
            *data = malloc(2 * sizeof(unsigned char*));
            **data = *tempData;
            *(*data + 1) = *envpData;
            *keys = malloc(sizeof(unsigned char*));
            **keys = *envpCryptKey;
            break;
    }

    return success;
}

bool ParseFile(enum FileTypes fileType, const char* fileName, char*** keyLengths, unsigned char*** keys, unsigned char*** iv, unsigned char*** modulus, unsigned char*** pe, unsigned char*** se, unsigned char*** sign, unsigned char*** data, unsigned char*** envpData, unsigned char*** envpCryptKey, unsigned char*** encFilePath)
{
    unsigned char* text = NULL;
    unsigned char* output = NULL;
    unsigned char**** pointer = NULL;
    bool checkDescription = false;
    bool checkMethods = false;
    bool continuous = false;
    char errorDescription[100];

    int size = ReadFile(fileName, &text, 0);
    if(size == 0)
        return false;

    bool error = false;

    enum ParseTypes tempParseType;
    bool commentingAllowed = true;
    int line = 0;
    int numOfElem = 0;

    for (unsigned char *p = StrTok(text, '\n'); p != NULL && !error; p = StrTok(NULL, '\n'))
    {
        line++;
        tempParseType = ParseLine(p, &output);
        switch(tempParseType)
        {
            case EMPTY_LINE:
                continue;
                break;
            case COMMENT:
                if(commentingAllowed)
                    continue;
                else
                {
                    sprintf(errorDescription, "%s. Comment at line %d.", fileName, line);
                    error = true;
                }
                break;
            case BEGIN_CRYPTO:
                commentingAllowed = false;
                break;
            case END_CRYPTO:
                commentingAllowed = true;
                break;
            case KEY:
                numOfElem = 0;
                checkMethods = false;
                checkDescription = false;
                continuous = false;
                if(!strcmp((char*) output, DESCRIPTION))
                    checkDescription = true;
                else if(!strcmp((char*) output, FILE_NAME))
                    pointer = &encFilePath;
                else if(!strcmp((char*) output, METHOD))
                    checkMethods = true;
                else if(!strcmp((char*) output, KEY_LENGTH))
                    pointer = (unsigned char****) &keyLengths;
                else if(!strcmp((char*) output, SECRET_KEY))
                    pointer = &keys;
                else if(!strcmp((char*) output, INITIALIZATION_VECTOR))
                    pointer = &iv;
                else if(!strcmp((char*) output, MODULUS))
                {
                    continuous = true;
                    pointer = &modulus;
                } 
                else if(!strcmp((char*) output, PUBLIC_EXPONENT))
                {
                    continuous = true;
                    pointer = &pe;
                }
                else if(!strcmp((char*) output, PRIVATE_EXPONENT))
                {
                    continuous = true;
                    pointer = &se;
                }
                else if(!strcmp((char*) output, SIGNATURE))
                {
                    continuous = true;
                    pointer = &sign;
                }
                else if(!strcmp((char*) output, DATA))
                {
                    continuous = true;
                    pointer = &data;
                }
                else if(!strcmp((char*) output, ENVELOPE_DATA))
                {
                    continuous = true;
                    pointer = &envpData;
                }
                else if(!strcmp((char*) output, ENVELOPE_CRYPT_KEY))
                {
                    continuous = true;
                    pointer = &envpCryptKey;
                } 
                break;
            case VALUE:
                if(checkMethods && !CheckMethods((char*) output, fileType))
                {
                    error = true;
                    sprintf(errorDescription, "%s. Wrong method at line %d, needs to be %s.", fileName, line, FileTypeMethods[(int) fileType]);
                }
                if(checkDescription && strcmp(FileTypeDescription[(int) fileType], (char*) output))
                {
                    error = true;
                    sprintf(errorDescription, "%s. Wrong description at line %d, needs to be %s.", fileName, line, FileTypeDescription[(int) fileType]);
                }
                if(pointer == NULL)
                    continue;
                if(**pointer == NULL)
                    **pointer = calloc((numOfElem + 1), sizeof(unsigned char*));
                else
                {
                    if(continuous == false)
                    {
                        unsigned char** nTemp = realloc(**pointer, (numOfElem + 1) * sizeof(unsigned char*));
                        if(nTemp != NULL)
                            **pointer = nTemp;
                        else
                            free(**pointer);
                    }
                    else
                    {
                        int oSize = FieldSize(output);
                        int cSize = FieldSize(*(**pointer + numOfElem));
                        unsigned char* temp = realloc(*(**pointer + numOfElem), (cSize + oSize + 2) * sizeof(unsigned char));

                        if(temp != NULL)
                        {
                            *(**pointer + numOfElem) = temp;
                        }
                        else
                            free(*(**pointer + numOfElem));
                        strncat((char*) *(**pointer + numOfElem), (char*) output, oSize);
                        strncat((char*) *(**pointer + numOfElem), "\n", 1);

                        continue;
                    }                  
                }
                int outputSize = FieldSize(output);
                if(continuous == false)
                    *(**pointer + numOfElem) = (unsigned char*) calloc(outputSize + 1, sizeof(unsigned char));
                else
                    *(**pointer + numOfElem) = (unsigned char*) calloc(outputSize + 2, sizeof(unsigned char));
                strncpy((char*) *(**pointer + numOfElem), (char*) output, outputSize);

                if(!continuous)
                    numOfElem++;
                else
                    strncat((char*) *(**pointer + numOfElem), "\n", 1);
                break;
        }
    }

    free(output);
    free(text);
    if(error)
        ErrorHandler(PARSEERROR, errorDescription);
    return !error;
}

bool CheckMethods(char* method, enum FileTypes fileType)
{
    const char* const typeMethods = FileTypeMethods[(int)fileType];

    char* iter;
    char*p = strchr(typeMethods, ',');
    char* lastPlace = (char*) typeMethods;
    do
    {
        int size = (p != NULL) ? p - lastPlace : strlen(lastPlace);
        iter = (char*) calloc(size + 1, sizeof(char));
        strncpy(iter, lastPlace, size);
        if(!strcmp(method, iter))
            return true;
        free(iter);
        if(p == NULL)
            break;
        p++;
        lastPlace = p;
        p = strchr(lastPlace, ',');
    }while(p != NULL || strlen(lastPlace) > 0);

    return false;
}

enum ParseTypes ParseLine(unsigned char* line, unsigned char** output)
{
    if(line == NULL)
        return EMPTY_LINE;
    
    int lineSize = FieldSize((char*) line);
    int paddingSize = FieldSize((char*) valuePadding);

    if(!strcmp((char*) line, BEGIN_FILE))
        return BEGIN_CRYPTO;
    if(!strcmp((char*) line, END_FILE))
        return END_CRYPTO;

    if(!strcmp((char*) line, DESCRIPTION) || !strcmp((char*) line, FILE_NAME) || !strcmp((char*) line, METHOD) || !strcmp((char*) line, KEY_LENGTH) || !strcmp((char*) line, SECRET_KEY) || !strcmp((char*) line, INITIALIZATION_VECTOR) || 
        !strcmp((char*) line, MODULUS) || !strcmp((char*) line, PUBLIC_EXPONENT) || !strcmp((char*) line, PRIVATE_EXPONENT) || !strcmp((char*) line, SIGNATURE) || !strcmp((char*) line, DATA) || !strcmp((char*) line, ENVELOPE_DATA) || !strcmp((char*) line, ENVELOPE_CRYPT_KEY))
    {
        unsigned char *returnValue = (unsigned char*)calloc(lineSize + 1, sizeof(unsigned char));
        strncpy((char*) returnValue, (char*) line, lineSize + 1);
        *output = returnValue;
        return KEY;
    }
    
    unsigned char *ptr = (unsigned char*) strstr((char*) line, valuePadding);
    int position = ptr - line;

    if(position == 0 && lineSize > paddingSize && !isspace(line[paddingSize]))
    {
        int difference = lineSize - paddingSize + 1;
        unsigned char *returnValue = (unsigned char*)calloc(difference, sizeof(unsigned char));
        strncpy((char*) returnValue, (char*) ptr + paddingSize, difference);
        *output = returnValue;
        return VALUE;
    }

    int inc = 0;
    for(unsigned char* iterator = line; isspace(*iterator); iterator++)
        inc++;

    if(inc == lineSize)
        return EMPTY_LINE;
    else
        return COMMENT;
}

unsigned char* StrTok(unsigned char* text, char delim)
{
    int size = 0;
    unsigned char* returnValue;
    if(text == NULL)
    {
        if(strokPointer != NULL)
            text = ++strokPointer;
        else
            return NULL;
    }
    strokPointer = (unsigned char*) strchr((char*) text, delim);
    if(strokPointer == NULL)
    {
        size = FieldSize(text);
        if(size == 0)
            return NULL;
    }
    else
        size = strokPointer - text;
    returnValue = (unsigned char*) calloc(size + 1, sizeof(unsigned char));
    strncpy((char*) returnValue, (char*) text, size);
    return returnValue;
}

