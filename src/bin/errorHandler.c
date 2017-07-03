#include "allInclusions.h"

void ErrorHandler(enum ErrorState error, const char *description)
{
    switch(error)
    {
        case ARGERROR:
            if(description == NULL)
                printf("\nArguments were not correct, try --help argument\n");
            else
                printf("\nArguments %s is not correct\n", description);
            break;
        case MALLOC:
            printf("\nAn error occured while allocating memory. %s\n", description);
            break;
        case INTCONVERSION:
            printf("\nInt conversion error. %s\n", description);
            break;
        case NOFILE:
            printf("\nThe file %s does not exist\n", description);
            break;
        case READERROR:
            printf("\nAn error occured whilst reading file: %s\n", description);
            break;    
        case WRITEERROR:
            printf("\nAn error occured whilst saving file: %s\n", description);
            break;
        case AESKEYLENGTH:
            printf("\nAES key length is improper %s\n", description);
            break;
        case AESIVLENGTH:
            printf("\nAES cbc IV length is improper\n");
            break;
        case EVPLIBRARY:
            printf("\nError occured whilst loading EVP library\n");
            break;
        case AESINIT:
            printf("\nError occured during initialization of AES algorithm\n");
            break;
        case AESENCRYPT:
            printf("\nError occured during AES encryption\n");
            break;
        case AESDECRYPT:
            printf("\nError occured during AES decryption, check the key\n");
            break;
        case SHAINIT:
            printf("\nError occured during initialization of SHA algorithm\n");
            break;
        case SHACALC:
            printf("\nError occured during calculation of SHA digest\n");
            break;
        case RSAKEYGENERATION:
            printf("\nError occured during RSA key generation\n");
            break;
        case RSAKEYLENGTH:
            printf("\nRSA key length is improper %s\n", description);
            break;
        case RSAENCODING:
            printf("\nData meant for encryption is too large.\n");
            break;
        case RSADECODING:
            printf("\nData meant for decryption is too large.\n");
            break;
        case B64ENCODE:
            printf("\nBase 64 encoding has failed\n");
            break;
        case B64DECODE:
            printf("\nBase 64 decoding has failed\n");
            break;
        case PARSEERROR:
            printf("\nAn error occured while parsing file %s\n", description);
            break;

        default:
            printf("\nUnknown error occured\n");
            break;
    }
    return;
}