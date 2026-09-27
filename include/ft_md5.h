#ifndef FT_MD5_H
#define FT_MD5_H

#include "./ft_ssl.h"

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define ROTL(x, c) (((x) << (c)) | ((x) >> (32 - (c)))) // Make sure to not pass 0

u_int32_t roundF(uint32_t x, uint32_t y, uint32_t z);
u_int32_t roundG(uint32_t x, uint32_t y, uint32_t z);
u_int32_t roundH(uint32_t x, uint32_t y, uint32_t z);
u_int32_t roundI(uint32_t x, uint32_t y, uint32_t z);

typedef struct s_md5_const
{
    uint32_t ac; // Addition constant ACt
    uint8_t  s;
    uint8_t  rc; // Rotation Constant RCt
}   t_md5_const;

typedef struct s_md5_ctx {
    uint32_t state[4];
    char md5rslt[33]; // 32 characters for the hash + 1 for the null terminator
    uint64_t bitlen;
    uint64_t bytelen;
    unsigned char buffer[64];
    t_md5_const md5const[64];
}  t_md5_ctx;


int         md5(char *input, const t_options options);
void        md5Compression(t_md5_ctx *ctx);
uint32_t    constructBlockLE(const unsigned char *buffer);
int         md5Update(t_md5_ctx *ctx, const unsigned char *data, size_t len);

#endif