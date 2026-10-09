#ifndef FT_SHA1_H
#define FT_SHA1_H

#include "./ft_ssl.h"
#include "./ft_utils.h"

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define ROTL(x, c) (((x) << (c)) | ((x) >> (32 - (c)))) // Make sure to not pass 0


u_int32_t SHA1roundF(uint32_t x, uint32_t y, uint32_t z);
u_int32_t SHA1roundG(uint32_t x, uint32_t y, uint32_t z);
u_int32_t SHA1roundH(uint32_t x, uint32_t y, uint32_t z);
u_int32_t SHA1roundI(uint32_t x, uint32_t y, uint32_t z);

typedef struct s_sha1_ctx {
    uint32_t state[5];
    char sha1rslt[41];
    uint64_t bitlen;
    uint64_t bytelen;
    unsigned char buffer[64];
}  t_sha1_ctx;


void        sha1(const char *input, size_t len, const char *label, bool is_string, const t_options options, bool is_file);
void        sha1Compression(t_sha1_ctx *ctx);
uint32_t    constructBlockBE(const unsigned char *buffer);
void        sha1Update(t_sha1_ctx *ctx, const unsigned char *data, size_t len);
void        sha1Final(t_sha1_ctx *ctx, const t_options options, const char *input);
void        sha1Pad(t_sha1_ctx *ctx);
void        sha1(const char *input, size_t len, const char *label, bool is_string, const t_options options, bool is_file);
#endif