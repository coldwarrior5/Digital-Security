#ifndef SHA256_H_
#define SHA256_H_

typedef struct {
   unsigned char data[64];
   uint datalen;
   uint bitlen[2];
   uint state[8];
} MSHA256_CTX;

void sha256_transform(MSHA256_CTX *ctx, unsigned char data[]);
void sha256_init(MSHA256_CTX *ctx);
void sha256_update(MSHA256_CTX *ctx, unsigned char data[], uint len);
void sha256_final(MSHA256_CTX *ctx, unsigned char hash[]);

#endif
