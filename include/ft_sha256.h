#ifndef FT_SHA256_H
#define FT_SHA256_H

#include "./ft_ssl.h"


// TODO: Make sure to not pass 0 as rotation count
#define ROTL(x, c)  (((x) << (c)) | ((x) >> (32 - (c))))    // circular left shift
#define ROTR(x, c)  (((x) >> (c)) | ((x) << (32 - (c))))    // circular right shift
#define SHR(x, c)   ((x) >> (c))                            // right shift operation where c 0 <= x < 32

u_int32_t Ch(uint32_t x, uint32_t y, uint32_t z);
u_int32_t Maj(uint32_t x, uint32_t y, uint32_t z);
u_int32_t Sigma0(uint32_t x);
u_int32_t Sigma1(uint32_t x);
uint32_t  sigma0(uint32_t x);
uint32_t  sigma1(uint32_t x);

typedef struct s_sha256_ctx {
    uint32_t        state[8];
    char            sha256rslt[65];
    uint64_t        bitlen;
    uint64_t        bytelen;
    unsigned char   buffer[64];
    uint32_t  sha256const[64];
}  t_sha256_ctx;


int         sha256(char *input, const t_options options);
void        sha256Compression(t_sha256_ctx *ctx);
uint32_t    constructBlockBE(const unsigned char *buffer);
int         sha256Update(t_sha256_ctx *ctx, const unsigned char *data, size_t len);


int sha256(char *input, const t_options options);


#endif