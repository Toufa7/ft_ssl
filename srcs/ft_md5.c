#include "../include/ft_md5.h"

static const uint32_t g_md5[4] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476
};


/*
    Doc: 2^32*abs(sin(i)), where i is in radians
*/
static const t_md5_const g_md5const[64] = {
    // Round 1
    {0xd76aa478, 7, 0},
    {0xe8c7b756, 12, 1},
    {0x242070db, 17, 2},
    {0xc1bdceee, 22, 3}, 
    {0xf57c0faf, 7, 4}, 
    {0x4787c62a, 12, 5}, 
    {0xa8304613, 17, 6},
    {0xfd469501, 22, 7}, 
    {0x698098d8, 7, 8}, 
    {0x8b44f7af, 12, 9}, 
    {0xffff5bb1, 17, 10}, 
    {0x895cd7be, 22, 11},
    {0x6b901122, 7, 12},
    {0xfd987193, 12, 13},
    {0xa679438e, 17, 14},
    {0x49b40821, 22, 15},
    // Round 2
    {0xf61e2562, 5, 1},
    {0xc040b340, 9, 6},
    {0x265e5a51, 14, 11},
    {0xe9b6c7aa, 20, 0},
    {0xd62f105d, 5, 5},
    {0x02441453, 9, 10},
    {0xd8a1e681, 14, 15},
    {0xe7d3fbc8, 20, 4},
    {0x21e1cde6, 5, 9},
    {0xc33707d6, 9, 14},
    {0xf4d50d87, 14, 3},
    {0x455a14ed, 20, 8},
    {0xa9e3e905, 5, 13},
    {0xfcefa3f8, 9, 2},
    {0x676f02d9, 14, 7},
    {0x8d2a4c8a, 20, 12},
    // Round 3
    {0xfffa3942, 4, 5},
    {0x8771f681, 11, 8},
    {0x6d9d6122, 16, 11},
    {0xfde5380c, 23, 14},
    {0xa4beea44, 4, 1},
    {0x4bdecfa9, 11, 4},
    {0xf6bb4b60, 16, 7},
    {0xbebfbc70, 23, 10},
    {0x289b7ec6, 4, 13},
    {0xeaa127fa, 11, 0},
    {0xd4ef3085, 16, 3},
    {0x04881d05, 23, 6},
    {0xd9d4d039, 4, 9},
    {0xe6db99e5, 11, 12},
    {0x1fa27cf8, 16, 15},
    {0xc4ac5665, 23, 2},
    // Round 4
    {0xf4292244, 6, 0},
    {0x432aff97, 10, 7},
    {0xab9423a7, 15, 14},
    {0xfc93a039, 21, 5},
    {0x655b59c3, 6, 12},
    {0x8f0ccc92, 10, 3},
    {0xffeff47d, 15, 10},
    {0x85845dd1, 21, 1},
    {0x6fa87e4f, 6, 8},
    {0xfe2ce6e0, 10, 15},
    {0xa3014314, 15, 6},
    {0x4e0811a1, 21, 13},
    {0xf7537e82, 6, 4},
    {0xbd3af235, 10, 11},
    {0x2ad7d2bb, 15, 2},
    {0xeb86d391, 21, 9}
};

u_int32_t roundF(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) | (~x & z));
}
u_int32_t roundG(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & z) | (y & ~z));
}
u_int32_t roundH(uint32_t x, uint32_t y, uint32_t z) {
    return (x ^ y ^ z);
}
u_int32_t roundI(uint32_t x, uint32_t y, uint32_t z) {
    return (y ^ (x | ~z));
}

int md5Init(t_md5_ctx *ctx) {
    memset(ctx, 0, sizeof(t_md5_ctx));
    memcpy(ctx->state, g_md5, sizeof(g_md5));
    memcpy(ctx->md5const, g_md5const, sizeof(g_md5const));
    return 0;
}

void md5Pad(t_md5_ctx *ctx) {
    unsigned char *buffer = ctx->buffer;
    uint64_t input_len = ctx->bytelen;

    if (ctx->bitlen == 512) {
        md5Compression(ctx);
        ctx->bitlen = 0;
    }

    size_t zeros = (447 - ctx->bitlen) % 512;
#ifdef DEBUG
    log_debug("Padding MD5 with %zu bits of data, zeros to be added: %zu", ctx->bitlen, zeros);
#endif
    buffer[ctx->bitlen / 8] = 0x80;
    ctx->bitlen += 8;

    for (size_t i = 0; i < (zeros - 7) / 8; i++) {
        if (ctx->bitlen == 512) {
            md5Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[(ctx->bitlen / 8)] = 0x00;
        ctx->bitlen += 8;
    }

    for (size_t i = 0; i < 8; i++) {
        if (ctx->bitlen == 512) {
            md5Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[ctx->bitlen / 8] = input_len >> (i * 8);
        ctx->bitlen += 8;
    }
    md5Compression(ctx);
}

int md5Update(t_md5_ctx *ctx, const unsigned char *data, size_t len) {
#ifdef DEBUG
    log_info("%s", (len * 8 > 512 - ctx->bitlen) ? "Data exceeds buffer size, processing in chunks" : "Data fits in buffer, processing directly");
#endif
    ctx->bytelen += (uint64_t)len * 8;

    size_t offset = 0;
    while ((len - offset) * 8 > 512 - ctx->bitlen) {
        size_t chunk_size = (512 - ctx->bitlen) / 8;
        memcpy(&ctx->buffer[ctx->bitlen / 8], &data[offset], chunk_size);
#ifdef DEBUG
        log_debug("Processing chunk of size: %zu bytes, data: [%s]", chunk_size, &data[offset]);
#endif
        ctx->bitlen += chunk_size * 8;
        offset += chunk_size;
        md5Compression(ctx);
#ifdef DEBUG
        log_debug("Current offset: %zu, bitlen: %llu, bytelen: %llu", offset, ctx->bitlen, ctx->bytelen);
#endif
        ctx->bitlen = 0;
    }
    memcpy(&ctx->buffer[ctx->bitlen / 8], &data[offset], len - offset);
    ctx->bitlen += (len - offset) * 8;
    return 0;
}

// Little endian 
uint32_t constructBlockLE(const unsigned char *buffer) {
    uint32_t block;
    memset(&block, 0, sizeof(block));
    for (size_t i = 0; i < 4; i++){
        block |= (uint32_t)buffer[i] << (i * 8);
    }
    return block;
}

void md5Compression(t_md5_ctx *ctx) {
    uint32_t M[16];

    memset(M, 0, sizeof(M));
    // Breaking our ctx->buffer into 16 32 bit words (4 bytes need to be combinted into 1 word)
    for (size_t i = 0; i < 16; i++) {
        M[i] = constructBlockLE(&ctx->buffer[i * 4]);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];

    for (size_t j = 0; j < 64; j++) {
        uint32_t    non_linear;
        if (j < 16) {
            non_linear = roundF(b, c, d);
        } else if (j < 32) {
            non_linear = roundG(b, c, d);
        } else if (j < 48) {
            non_linear = roundH(b, c, d);
        } else {
            non_linear = roundI(b, c, d);
        }
        // B gets the new value of A, C gets the old value of B, D gets the old value of C, and A gets the new value of D
        uint32_t temp = d;
        d = c;
        c = b;
        b = b + (ROTL((a + non_linear + M[ctx->md5const[j].rc] + ctx->md5const[j].ac), ctx->md5const[j].s));
        a = temp;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

void md5(const char *input, size_t len, const char *label, bool is_string, const t_options options, bool is_file)
{
    t_md5_ctx ctx;
    md5Init(&ctx);
    md5Update(&ctx, (const unsigned char *)input, len);
    md5Pad(&ctx);
    size_t pos = 0;
    for (size_t i = 0; i < 4; i++) {
        uint32_t word = ctx.state[i];
        for (size_t b = 0; b < 4; b++) {
            pos += sprintf(&ctx.md5rslt[pos], "%02x", (word >> (b * 8)) & 0xFF);
        }
    }
    printHash("MD5", ctx.md5rslt, is_string, options, is_file, label);
}