#ifndef ERRORHANDLER_H_
#define ERRORHANDLER_H_

enum ErrorState
{
    ARGERROR,
    MALLOC,
    INTCONVERSION,
    NOFILE,
    READERROR,
    WRITEERROR,
    AESKEYLENGTH,
    AESIVLENGTH,
    EVPLIBRARY,
    AESINIT,
    AESENCRYPT,
    AESDECRYPT,
    SHAINIT,
    SHACALC,
    SHAALLOC,
    RSAKEYGENERATION,
    RSAKEYLENGTH,
    RSAENCODING,
    RSADECODING,
    B64ENCODE,
    B64DECODE,
    PARSEERROR
};

void ErrorHandler(enum ErrorState error, const char *description);

#endif