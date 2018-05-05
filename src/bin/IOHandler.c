#include "allInclusions.h"

// Print string as hex string
void HexPrint(unsigned char* input, int length)
{
    unsigned char *p = input;
    if (NULL == input)
        printf("NULL");
    else
    {
	int i;
        for(i = 0; i < length; i++)
            printf("%02X ", *p++);
    }
    printf("\n");
}

void PrintKeys(const char* const fileName)
{
    int keys = 0;
    char *aesPath = DefinePath(KEY_LOCATION, fileName, AES_KEY_EXTENSION);
    char *rsaPublicPath = DefinePath(KEY_LOCATION, fileName, RSA_PUBLIC_KEY_EXTENSION);
    char *rsaSecretPath = DefinePath(KEY_LOCATION, fileName, RSA_SECRET_KEY_EXTENSION);

    if (access(aesPath, F_OK | R_OK) == 0)
    {
        printf("\nAES key\n");
        DisplayFile(aesPath, 0);
        keys++;
    }
        
    if (access(rsaPublicPath, F_OK | R_OK) == 0)
    {
        printf("\nRSA public key\n");
        DisplayFile(rsaPublicPath, 0);
        keys++;
    }

    if (access(rsaSecretPath, F_OK | R_OK) == 0)
    {
        printf("\nRSA secret key\n");
        DisplayFile(rsaSecretPath, 0);
        keys++;
    }

    if(keys == 0)
        ErrorHandler(NOFILE, fileName);
}

void PrintFiles(const char* const fileName, char encrypted)
{
    int keys = 0;
    char *filePath = DefinePath(FILE_LOCATION, fileName, TEXT_EXTENSION);
    char *decryptedPath = DefinePath(DECRYPTED_LOCATION, fileName, TEXT_EXTENSION);

    char *aesPath = DefinePath(ENCRYPTED_LOCATION, fileName, AES_ENCRYPTION_EXTENSION);
    char *rsaPath = DefinePath(ENCRYPTED_LOCATION, fileName, RSA_ENCRYPTION_EXTENSION);
    char *shaPath = DefinePath(ENCRYPTED_LOCATION, fileName, SHA_DIGEST_EXTENSION);
    char *envelopePath = DefinePath(ENCRYPTED_LOCATION, fileName, ENVELOPE_EXTENSION);
    char *signaturePath = DefinePath(ENCRYPTED_LOCATION, fileName, SIGNATURE_EXTENSION);
    char *sealPath = DefinePath(ENCRYPTED_LOCATION, fileName, SEAL_EXTENSION);

    if(encrypted == 1)
    {
        if (access(aesPath, F_OK | R_OK) == 0)
        {
            printf("\nAES encrypted file\n");
            DisplayFile(aesPath, 0);
            keys++;
        } 
        if (access(rsaPath, F_OK | R_OK) == 0)
        {
            printf("\nRSA encrypted file\n");
            DisplayFile(rsaPath, 0);
            keys++;
        }
        if (access(shaPath, F_OK | R_OK) == 0)
        {
            printf("\nSha digest\n");
            DisplayFile(shaPath, 0);
            keys++;
        }  
        if (access(envelopePath, F_OK | R_OK) == 0)
        {
            printf("\nDigital envelope\n");
            DisplayFile(envelopePath, 0);
            keys++;
        }
        if (access(signaturePath, F_OK | R_OK) == 0)
        {
            printf("\nDigital signature\n");
            DisplayFile(signaturePath, 0);
            keys++;
        }
        if (access(sealPath, F_OK | R_OK) == 0)
        {
            printf("\nDigital seal\n");
            DisplayFile(sealPath, 0);
            keys++;
        }
    }
    else
    {
        if (access(filePath, F_OK | R_OK) == 0)
        {
            printf("\nInput file\n");
            DisplayFile(filePath, 0);
            keys++;
        }
        if (access(decryptedPath, F_OK | R_OK) == 0)
        {
            printf("\nDecrypted file\n");
            DisplayFile(decryptedPath,0);
            keys++;
        }
    }
    if(keys == 0)
        ErrorHandler(NOFILE, fileName);
}

void DisplayFile(const char* const fileName, char binary)
{
    unsigned char* buffer = NULL;
    int readSize = ReadFile(fileName, &buffer, binary);
    
    if (readSize != 0)
    {
        if(binary == 1)
            HexPrint(buffer, readSize);
        else
            printf("%s", buffer);
        free(buffer);
    }
    return;
}

int ReadFile(const char* const fileName, unsigned char** buffer, char binary)
{
    if (access(fileName, F_OK | R_OK) != 0)
    {
        ErrorHandler(NOFILE, fileName);
        *buffer = NULL;
        return 0;
    }
    
	int stringSize = 0, readSize = -1;
	FILE *handler = NULL;
    if(binary == 1)
	    handler = fopen(fileName, "rb");
    else
        handler = fopen(fileName, "r");

    if(handler)
    {
        fseek(handler, 0, SEEK_END);
        stringSize = ftell(handler);
        rewind(handler);

        unsigned char* tempBuffer = (unsigned char*)malloc(sizeof(unsigned char) * (stringSize + 1));
        readSize = fread(tempBuffer, sizeof(unsigned char), stringSize, handler);
        tempBuffer[stringSize] = '\0';
        *buffer = tempBuffer;
        fclose(handler);
    }

    if (stringSize != readSize)
    {  
        ErrorHandler(READERROR, fileName);
        free(*buffer);
        *buffer = NULL;
    }
    
    return readSize;;
}

bool SaveToFile(unsigned char* text, int length, const char* const destinationFile, char binary, char overwrite)
{
    
    if (access(destinationFile, F_OK) == 0 && !overwrite)
    {
        char input[5];
        printf("Do you wish to overwrite existing file? [N/y] ");
        fgets(input, 5, stdin);
        if(input[0] != 'y')
            return false;
    }
    

    FILE *handler = NULL;
    if(binary == 1)
        handler = fopen(destinationFile, "wb");
    else
        handler = fopen(destinationFile, "w");

    if (handler)
    {
        fwrite(text, sizeof(unsigned char), length, handler);
        fclose(handler);
    }
    else
    {
        ErrorHandler(WRITEERROR, destinationFile);
        return false;
    }
    
    return true;
}

void CopyFile(const char* const sourceFile, const char* const destinationFile, char binary)
{
    unsigned char *buffer = NULL;
    int readSize = ReadFile(sourceFile, &buffer, binary);

    if(readSize == 0)
        return;

    SaveToFile(buffer, readSize, destinationFile, binary, 0);

    free(buffer);
}

char* DefinePath(const char* const folder, const char* const filename, const char* const extension)
{
    char* str = (char *) malloc(sizeof(char) * (sizeof(folder) + sizeof(filename) + sizeof(extension) + 2));
    strcpy(str, folder);
    strcat(str, "/");
    strcat(str, filename);
    strcat(str, extension);
    return str;
}

void CheckTermination(char *input)
{
    if(!strcmp(input, "q") || !strcmp(input, "quit") || !strcmp(input, "stop") || !strcmp(input, "exit"))
        terminated = true;
}

int GetWidth(char *text)
{
    char* firstLine;
    sscanf(text, "%s", firstLine);
    return strlen(firstLine);
}

int GetHeight(char *text)
{
    char* line;
    int size = 0;
    char buff[1024] = {0};
    char *pch = NULL;
    strcpy(buff, text);
    pch = strtok(buff, "\n");
    while(pch != NULL)
    {
        size++;
        pch = strtok(NULL, "\n");
    }
    
    return size;
}

int FieldSize(void* field)
{
    unsigned char* pointer = (unsigned char*) field;
    if(pointer == NULL)
        return -1;
    int i = 0;
    int limit = 2000;
    int iter = 0;
    while(iter++ < limit && *(pointer + i) != '\0')
        i++;
    if(iter == limit)
        i = -1;
    return i;
}

char* Extension(char* filePath)
{
    char *temp = strrchr(filePath, '.');
        
    char* returnValue = calloc(strlen(temp) + 1, sizeof(char));
    strcpy(returnValue, temp);
    return returnValue;
}
