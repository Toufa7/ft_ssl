#include "../include/ft_sha512.h"

/*
    primesNbr = {2, 3, 5, 7, 11, 13, 17, 19}
    for (i in primesNbr) {
        getFractionalPart(sqrt(i), HEX))
    }
*/
static const uint64_t g_sha512[8] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
};



// ac = ₃√2 = 1.25992104989487316476721060727823
// Keeping only the fractional part
// ac = 0.25992104989487316476721060727823
// Convert it from binary to hex or use ubuntu calculator
// 01000010100010100010111110011001
// [428A2F98D728AE22]3DDAB715BE250D0C
static const uint64_t g_sha512const[80] = {
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817
};



uint64_t Ch_(uint64_t x, uint64_t y, uint64_t z) {
    return ((x & y) | (~x & z));
}
uint64_t Maj_(uint64_t x, uint64_t y, uint64_t z) {
    return ((x & y) ^ (x & z) ^ (y & z));
}

uint64_t Sigma0_(uint64_t x) {
    return (ROTR_(x, 28) ^ ROTR_(x, 34) ^ ROTR_(x, 39));
}
uint64_t Sigma1_(uint64_t x) {
    return (ROTR_(x, 14) ^ ROTR_(x, 18) ^ ROTR_(x, 41));
}
uint64_t  sigma0_(uint64_t x) {
    return (ROTR_(x, 1) ^ ROTR_(x, 8) ^ SHR_(x, 7));
}
uint64_t  sigma1_(uint64_t x) {
    return (ROTR_(x, 19) ^ ROTR_(x, 61) ^ SHR_(x, 6));
}


int sha512Init(t_sha512_ctx *ctx) {
    memset(ctx, 0, sizeof(t_sha512_ctx));
    memcpy(ctx->state, g_sha512, sizeof(g_sha512));
    memcpy(ctx->sha512const, g_sha512const, sizeof(g_sha512const));
    return 0;
}


void sha512Pad(t_sha512_ctx *ctx) {
    unsigned char *buffer = ctx->buffer;
    uint64_t input_len = ctx->bytelen;

    //printf("Padding SHA512 with %zu bits of data", ctx->bitlen);
    if (ctx->bitlen == 1024) {
        sha512Compression(ctx);
        ctx->bitlen = 0;
    }

    /*  zeros = (1024 - 1 - 128) - ctx->bitlen */
    size_t zeros = (895 - ctx->bitlen) % 1024;
    buffer[ctx->bitlen / 8] = 0x80;
    ctx->bitlen += 8;

    for (size_t i = 0; i < (zeros - 7) / 8; i++) {
        if (ctx->bitlen == 1024) {
            sha512Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[(ctx->bitlen / 8)] = 0x00;
        ctx->bitlen += 8;
    }


    for (size_t i = 0; i < 8; i++) {
        if (ctx->bitlen == 1024) {
            sha512Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[ctx->bitlen / 8] = 0x00;
        ctx->bitlen += 8;
    }

    for (size_t i = 0; i < 8; i++) {
        if (ctx->bitlen == 1024) {
            sha512Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[ctx->bitlen / 8] = (input_len >> ((7 - i) * 8));
        ctx->bitlen += 8;
    }
    sha512Compression(ctx);
}

void sha512Update(t_sha512_ctx *ctx, const unsigned char *data, size_t len){
#ifdef DEBUG
    printf("%s", (len * 8 > 1024 - ctx->bitlen) ? "Chunking data into 64-byte blocks" : "Data fits in a single block");
#endif
    ctx->bytelen += (uint64_t)len * 8;

    size_t offset = 0;
    while ((len - offset) * 8 > 1024 - ctx->bitlen) {
        size_t chunk_size = (1024 - ctx->bitlen) / 8;
        memcpy(&ctx->buffer[ctx->bitlen / 8], &data[offset], chunk_size);
#ifdef DEBUG
        printf("Processing chunk of size: %zu bytes, data: [%s]", chunk_size, &data[offset]);
#endif
        ctx->bitlen += chunk_size * 8;
        offset += chunk_size;
        
#ifdef DEBUG
        printf("Current offset: %zu", offset * 8);
#endif
        sha512Compression(ctx);
        ctx->bitlen = 0;
    }

    memcpy(&ctx->buffer[ctx->bitlen / 8], &data[offset], len - offset);
    ctx->bitlen += (len - offset) * 8;
}

// Big endian
uint64_t constructBlockBE64(const unsigned char *buffer) {
    uint64_t block;
    memset(&block, 0, sizeof(block));
    for (size_t i = 0; i < 8; i++){
        block |= (uint64_t)buffer[i] << ((7 - i) * 8);
    }
    return block;
}

void sha512Compression(t_sha512_ctx *ctx) {
    uint64_t M[80];

    memset(M, 0, sizeof(M));
    // Breaking our ctx->buffer into 64 32 bit words (4 bytes need to be combinted into 1 word)
    size_t i = 0;
    for (; i < 16; i++) {
        M[i] = constructBlockBE64(&ctx->buffer[i * 8]);
    }
    for (; i < 80; i++) {
        M[i] = sigma1_(M[i - 2]) + M[i - 7] + sigma0_(M[i - 15]) + M[i - 16];
    }

    uint64_t a = ctx->state[0];
    uint64_t b = ctx->state[1];
    uint64_t c = ctx->state[2];
    uint64_t d = ctx->state[3];
    uint64_t e = ctx->state[4];
    uint64_t f = ctx->state[5];
    uint64_t g = ctx->state[6];
    uint64_t h = ctx->state[7];

    for (size_t j = 0; j < 80; j++) {
        uint64_t    T1 = h + Sigma1_(e) + Ch_(e, f, g) + ctx->sha512const[j] + M[j];
        uint64_t    T2 = Sigma0_(a) + Maj_(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha512(const char *input, size_t len, const char *label, bool is_string, const t_options options, bool is_file)
{
    t_sha512_ctx ctx;
    sha512Init(&ctx);
    sha512Update(&ctx, (const unsigned char *)input, len);
    sha512Pad(&ctx);
    for (size_t i = 0; i < 8; i++) {
        snprintf(&ctx.sha512rslt[i * 16], 17, "%016llx", (unsigned long long)ctx.state[i]);
    }
    printHash("SHA512", ctx.sha512rslt, is_string, options, is_file, label);
}