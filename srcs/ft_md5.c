#include "../include/log.h"
#include "../include/ft_md5.h"

static const uint32_t g_md5[4] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476
};

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

// #define F(x, y, z) ((x & y) | (~x & z))
// #define G(x, y, z) ((x & z) | (y & ~z))
// #define H(x, y, z) (x ^ y ^ z)
// #define I(x, y, z) (y ^ (x | ~z))

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

int md5Update(t_md5_ctx *ctx, const unsigned char *data, size_t len) {
    memcpy(ctx->buffer, data, len);
    unsigned char *buffer = ctx->buffer;
    ctx->bitlen += (uint64_t)len * 8;
    uint64_t input_len = ctx->bitlen;
    log_debug("data=[%s]", data);
    for (size_t i = 0; i < len; i++) {
        printf("%08b ",data[i]);
        if ((i + 1) % 4 == 0)
            printf("\n");
    }
    printf("\n");
    size_t zeros = (447 - ctx->bitlen) % 512;
    log_debug("Msg contain %zu bits, we will add %zu zeros to make it 448 bits", ctx->bitlen, zeros);

    // Message input representation in bits that fits 64 bit
    log_debug("%064lb", ctx->bitlen);

    // Padding
        // 1 - Single 1 byte
    buffer[ctx->bitlen / 8] = 0x80;
    ctx->bitlen += 8;
    
        //2 - Append zeros 
    for (size_t i = 0; i < (zeros - 7) / 8; i++) {
        buffer[(ctx->bitlen / 8)] = 0x00;
        ctx->bitlen += 8;
    }

    log_debug("Total bits after padding: %zu", ctx->bitlen);

    // Appending the original length of the message as a 64-bit integer
    for (size_t i = 0; i < 8; i++) {
        buffer[ctx->bitlen / 8] = input_len >> (i * 8);
        ctx->bitlen += 8;
    }


    // Print the padded message in binary
    log_debug("Padded message in binary of length %zu in bits:", ctx->bitlen / 8);
    for (size_t i = 0; i < ctx->bitlen / 8; i++) {
        printf("%08b ", buffer[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    return 0;
}


uint32_t constructBlock(const unsigned char *buffer) {
    uint32_t block;
    memset(&block, 0, sizeof(block));
    for (size_t i = 0; i < 4; i++){
        block |= (uint32_t)buffer[i] << (i * 8);
    }
    return block;
}

int md5Compression(t_md5_ctx *ctx) {
    uint32_t M[16];

    memset(M, 0, sizeof(M));
    // Breaking our ctx->buffer into 16 32 bit words (4 bytes need to be combinted into 1 word)
    for (size_t i = 0; i < 16; i++) {
        M[i] = constructBlock(&ctx->buffer[i * 4]);
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
        b = b + (ROTL((a + non_linear + M[ctx->md5const[j].rc] + ctx->md5const[j].ac), ctx->md5const[j].s));        // ?? BLOCKED
        a = temp;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    return (0);
}

// int md5Final(t_md5_ctx *ctx) {
//     printf("MD5 digest: ");
//     for (size_t i = 0; i < 4; i++) {
//         printf("%08x", ctx->state[i]);
//     }
//     printf("\n");
//     return 0;
// }   


int md5Final(t_md5_ctx *ctx) {
    printf("MD5 digest: ");
    for (size_t i = 0; i < 4; i++) {
        uint32_t word = ctx->state[i];
        for (size_t b = 0; b < 4; b++) {
            printf("%02x", (word >> (b * 8)) & 0xFF);
        }
    }
    printf("\n");
    return 0;
}

int md5(char *input, const t_options options)
{
    t_md5_ctx ctx;
    md5Init(&ctx);
    log_info("MD5 function called");
    md5Update(&ctx, (const unsigned char *)input, strlen(input));
    md5Compression(&ctx);
    md5Final(&ctx);
    return 0;
}