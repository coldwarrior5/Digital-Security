#ifndef IOHandler_H_
#define IOHandler_H_

void HexPrint(unsigned char* input, int length);
void PrintKeys(const char* const fileName);
void PrintFiles(const char* fileName, char encrypted);
void DisplayFile(const char* fileName, char binary);
int ReadFile(const char* const fileName, unsigned char** buffer, char binary);
bool SaveToFile(unsigned char* text, int length, const char* const destinationFile, char binary, char overwrite);
void CopyFile(const char* const sourceFile, const char* const destinationFile, char binary);
char* DefinePath(const char* const folder, const char* const filename, const char* const extension);
void CheckTermination(char *input);
int GetWidth(char *text);
int GetHeight(char *text);
int FieldSize(void* field);
char* Extension(char* filePath);

#endif