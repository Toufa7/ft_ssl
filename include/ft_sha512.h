#ifndef FT_SHA512_H
#define FT_SHA512_H

#include "./ft_ssl.h"
#include "./ft_utils.h"


// TODO: Make sure to not pass 0 as rotation count
#define ROTL_(x, c)  (((x) << (c)) | ((x) >> (64 - (c))))    // circular left shift
#define ROTR_(x, c)  (((x) >> (c)) | ((x) << (64 - (c))))    // circular right shift
#define SHR_(x, c)   ((x) >> (c))                            // right shift operation where c 0 <= x < 64

uint64_t Ch_(uint64_t x, uint64_t y, uint64_t z);
uint64_t Maj_(uint64_t x, uint64_t y, uint64_t z);
uint64_t Sigma0_(uint64_t x);
uint64_t Sigma1_(uint64_t x);
uint64_t  sigma0_(uint64_t x);
uint64_t  sigma1_(uint64_t x);

typedef struct s_sha512_ctx {
    uint64_t        state[8];
    char            sha512rslt[129];
    uint64_t        bitlen;
    uint64_t        bytelen;
    unsigned char   buffer[128];
    uint64_t        sha512const[80];
}  t_sha512_ctx;


void        sha512(const char *input, size_t len, const char *label, bool is_string, const t_options options, bool is_file);
void        sha512Compression(t_sha512_ctx *ctx);
uint64_t    constructBlockBE64(const unsigned char *buffer);
void        sha512Update(t_sha512_ctx *ctx, const unsigned char *data, size_t len);
void        sha512Final(t_sha512_ctx *ctx, const t_options options, const char *input);
void        sha512Pad(t_sha512_ctx *ctx);

#endif