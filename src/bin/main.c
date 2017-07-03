#include "allInclusions.h"

void ProcessInputArguments(int argc, char *argv[]);
void InitFolders();
void InitKeysAndFiles();
bool CheckArgCount(int argc, int count);

const char* const description = "miscelaneous/description.txt";
const char* const testFile = "miscelaneous/testFiles/first.txt";
const char* const DEFAULT_NAME = "default";
const char* const DEFAULT_SENDER = "default_sender";
const char* const DEFAULT_RECEIVER = "default_receiver";

const char* const KEY_LOCATION = "keys";
const char* const FILE_LOCATION = "files";
const char* const ENCRYPTED_LOCATION = "encrypted";
const char* const DECRYPTED_LOCATION = "decrypted";

const char* const TEXT_EXTENSION = ".txt";
const char* const AES_KEY_EXTENSION = ".aes";
const char* const AES_ENCRYPTION_EXTENSION = ".eaes";
const char* const RSA_PUBLIC_KEY_EXTENSION = ".rsap";
const char* const RSA_SECRET_KEY_EXTENSION = ".rsas";
const char* const RSA_ENCRYPTION_EXTENSION = ".ersa";
const char* const SHA_DIGEST_EXTENSION = ".sha";
const char* const ENVELOPE_EXTENSION = ".envp";
const char* const SIGNATURE_EXTENSION = ".sign";
const char* const SEAL_EXTENSION = ".seal";

const char* const BEGIN_FILE = "---BEGIN OS2 CRYPTO DATA---";
const char* const END_FILE = "---END OS2 CRYPTO DATA---";
const char* const DESCRIPTION = "Description:";
const char* const FILE_NAME = "File name:";
const char* const METHOD = "Method:";
const char* const KEY_LENGTH = "Key length:";
const char* const SECRET_KEY = "Secret key:";
const char* const INITIALIZATION_VECTOR = "Initialization vector:";
const char* const MODULUS = "Modulus:";
const char* const PUBLIC_EXPONENT = "Public exponent:";
const char* const PRIVATE_EXPONENT = "Private exponent:";
const char* const SIGNATURE = "Signature:";
const char* const DATA = "Data:";
const char* const ENVELOPE_DATA = "Envelope data:";
const char* const ENVELOPE_CRYPT_KEY = "Envelope crypt key:";

int BASE = 10;
int BYTE = 8;
int AES_KEY_LENGTH = 128;
int AES_BLOCK_LENGTH = 128;
int RSA_KEY_LENGTH = 1024;
int RSA_PADDING = RSA_PKCS1_PADDING;
int MAX_FILE_SIZE = 4096;

typedef enum {COMMANDLINE, GUI, INLINE} RunMode;
RunMode mode = COMMANDLINE;
int returnCode = 0;

int main(int argc, char *argv[])
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
  OPENSSL_config(NULL);

  //InitFolders();
  //InitKeysAndFiles();
  ProcessInputArguments(argc, argv);
  if(mode == GUI)
    returnCode = GUIMode(argc, argv);
  else if (mode == COMMANDLINE)
    returnCode = CommandMode();
  
  return returnCode;
}

void InitFolders()
{
  struct stat sb;

  if (stat(KEY_LOCATION, &sb) != 0 || !S_ISDIR(sb.st_mode))
    mkdir(KEY_LOCATION, 0777);
  if (stat(FILE_LOCATION, &sb) != 0 || !S_ISDIR(sb.st_mode))
    mkdir(FILE_LOCATION, 0777);
  if (stat(ENCRYPTED_LOCATION, &sb) != 0 || !S_ISDIR(sb.st_mode))
    mkdir(ENCRYPTED_LOCATION, 0777);
  if (stat(DECRYPTED_LOCATION, &sb) != 0 || !S_ISDIR(sb.st_mode))
    mkdir(DECRYPTED_LOCATION, 0777);
}

void InitKeysAndFiles()
{
  char* inputFile = DefinePath(FILE_LOCATION, DEFAULT_NAME, TEXT_EXTENSION);
  char* aesKeyFile = DefinePath(KEY_LOCATION, DEFAULT_NAME, AES_KEY_EXTENSION);
  char* aesEncryptedFile = DefinePath(ENCRYPTED_LOCATION, DEFAULT_NAME, AES_ENCRYPTION_EXTENSION);
  char* rsaSenderPublicKeyFile = DefinePath(KEY_LOCATION, DEFAULT_SENDER, RSA_PUBLIC_KEY_EXTENSION);
  char* rsaSenderSecretKeyFile = DefinePath(KEY_LOCATION, DEFAULT_SENDER, RSA_SECRET_KEY_EXTENSION);
  char* rsaReceiverPublicKeyFile = DefinePath(KEY_LOCATION, DEFAULT_RECEIVER, RSA_PUBLIC_KEY_EXTENSION);
  char* rsaReceiverSecretKeyFile = DefinePath(KEY_LOCATION, DEFAULT_RECEIVER, RSA_SECRET_KEY_EXTENSION);

  // Copy the default file needed for encryption
  if (access(inputFile, F_OK | R_OK) != 0)
    CopyFile(testFile, inputFile, 0);
  // Generate AES key and encrypted file
  if (access(aesKeyFile, F_OK | R_OK) != 0)
    GUIGenerateAESKey(AES_KEY_LENGTH, AES_BLOCK_LENGTH, (char*)DEFAULT_NAME);
  // Generate RSA keys for sender
  if (access(rsaSenderPublicKeyFile, F_OK | R_OK) != 0 || access(rsaSenderSecretKeyFile, F_OK | R_OK) != 0 ) 
    GUIGenerateRSAKeys(RSA_KEY_LENGTH, DEFAULT_SENDER, 0);
  // Generate RSA keys for sender
  if (access(rsaReceiverPublicKeyFile, F_OK | R_OK) != 0 || access(rsaReceiverSecretKeyFile, F_OK | R_OK) != 0 ) 
    GUIGenerateRSAKeys(RSA_KEY_LENGTH, DEFAULT_RECEIVER, 0);
  
  return;
}

void ProcessInputArguments(int argc, char *argv[])
{
  if(argc < 2)
    return;

  mode = INLINE;

  if(!strcmp(argv[1], "-i"))
    mode = GUI;

  else if(!strcmp(argv[1], "-aes"))
  {
    if(!CheckArgCount(argc, 3))
      return;
      
    char *endptr;
	  long keyLength = strtol(argv[2], &endptr, BASE);
    if (endptr == argv[2] || ((keyLength != 128 && keyLength != 192 && keyLength != 256) && errno == ERANGE))
    {
      ErrorHandler(ARGERROR, "Key has to be either 128, 192, or 256 bits");
      return;
    }
    long blockLength = strtol(argv[3], &endptr, BASE);
    if (endptr == argv[3] || ((blockLength != 128 && blockLength != 192 && blockLength != 256) && errno == ERANGE))
    {
      ErrorHandler(ARGERROR, "IV has to be 128 bits");
      return;
    }

    unsigned char* key = GUIGenerateAESKey((int) keyLength, (int) blockLength, argv[4]);
    if(key != NULL)
    {
      printf("\nAES key: ");
      HexPrint(key, keyLength/BYTE);
    }
  }
  else if(!strcmp(argv[1], "-eaes"))
  {
    if(!CheckArgCount(argc, 3))
      return;

    GUIAESEncryption(argv[2], argv[3], argv[4], 1);
  }
  else if(!strcmp(argv[1], "-daes"))
  {
    if(!CheckArgCount(argc, 3))
      return;

    GUIAESDecryption(argv[2], argv[3], argv[4], 1);
  }
  else if(!strcmp(argv[1], "-rsa"))
  {
    if(!CheckArgCount(argc, 2))
      return;
      
    char *endptr;
	  long keyLength = strtol(argv[2], &endptr, BASE);
    if (endptr == argv[2] || ((keyLength != 1024 && keyLength != 2048 && keyLength != 3072) && errno == ERANGE))
    {
      ErrorHandler(ARGERROR, "Key has to be either 1024, 2048, or 3072 bits");
      return;
    }

    GUIGenerateRSAKeys((int) keyLength, argv[3], 1);
  }
  else if(!strcmp(argv[1], "-ersa"))
  {
    if(!CheckArgCount(argc, 3))
      return;

    GUIRSAEncryption(argv[2], argv[3], argv[4], 0, 1);
  }
  else if(!strcmp(argv[1], "-drsa"))
  {
    if(!CheckArgCount(argc, 3))
      return;

    GUIRSADecryption(argv[2], argv[3], argv[4], 0, 1);
  }
  else if(!strcmp(argv[1], "-sha"))
  {
    if(!CheckArgCount(argc, 2))
      return;

    unsigned char* digest = NULL;
    int digestLen = 0;
    bool success = GUISHADigest(argv[2], argv[3], &digest, &digestLen, 0, 1);
    if(success)
    {
      printf("\nMessage digest: %s", digest);
    }
  }
  else if(!strcmp(argv[1], "-sign"))
  {
    if(!CheckArgCount(argc, 3))
      return;

    GUISignature(argv[2], argv[3], argv[4], 1);
  }
  else if(!strcmp(argv[1], "-osign"))
  {
    if(!CheckArgCount(argc, 3))
      return;
    bool valid;
    GUICheckSignature(argv[2], argv[3], argv[4], &valid, 1);
    if(valid)
      printf("\nThe message is true.\n");
    if(!valid)
      printf("\nThe message was tampered.\n");

  }
  else if(!strcmp(argv[1], "-seal"))
  {
    mode = INLINE;
  }
  else if(!strcmp(argv[1], "-oseal"))
  {
    mode = INLINE;
  }
  else if(!strcmp(argv[1], "-envp"))
  {
    if(!CheckArgCount(argc, 3))
      return;

    GUIEnvelope(argv[2], argv[3], argv[4], 1);
  }
  else if(!strcmp(argv[1], "-oenvp"))
  {
    if(!CheckArgCount(argc, 3))
      return;

    GUIOpenEnvelope(argv[2], argv[3], argv[4], 1);
  }
  else if(!strcmp(argv[1], "-rdkey"))
  {
    if(!CheckArgCount(argc, 1))
      return;
    PrintKeys(argv[2]);
  }
  else if(!strcmp(argv[1], "-rdclr"))
  {
    if(!CheckArgCount(argc, 1))
      return;
    PrintFiles(argv[2], 0);
  }
  else if(!strcmp(argv[1], "-rdenc"))
  {
    if(!CheckArgCount(argc, 1))
      return;
    PrintFiles(argv[2], 1);
  }
  else if(!strcmp(argv[1], "-sha2"))
  {
    if(!CheckArgCount(argc, 2))
      return;

    unsigned char* digest = NULL;
    int digestLen = 0;
    bool success = GUISHADigest(argv[2], argv[3], &digest, &digestLen, 1, 1);
    if(success)
    {
      printf("\nMessage digest: %s", digest);
    }
  }
  else if(!strcmp(argv[1], "--help") || !strcmp(argv[1], "-?"))
    DisplayFile(description, 0);

  else
    ErrorHandler(ARGERROR, NULL);
    
  return;
}

bool CheckArgCount(int argc, int count)
{
  if(argc < count + 2)
  {
    ErrorHandler(ARGERROR, NULL);
    return false;
  }
    
  return true;
}