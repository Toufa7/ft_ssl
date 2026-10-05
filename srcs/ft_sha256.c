#include "../include/ft_sha256.h"


/*
    primesNbr = {2, 3, 5, 7, 11, 13, 17, 19}
    for (i in primesNbr) {
        getFractionalPart(sqrt(i), HEX))
    }
*/
static const uint32_t g_sha256[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};



// ac = ₃√2 = 1.25992104989487316476721060727823
// Keeping only the fractional part
// ac = 0.25992104989487316476721060727823
// Convert it from binary to hex
// 01000010100010100010111110011001
// [428A2F98]D728AE223DDAB715BE250D0C
static const uint32_t g_sha256const[64] = {
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2
};



u_int32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) | (~x & z));
}
u_int32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) ^ (x & z) ^ (y & z));
}

u_int32_t Sigma0(uint32_t x) {
    return (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22));
}
u_int32_t Sigma1(uint32_t x) {
    return (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25));
}
uint32_t  sigma0(uint32_t x) {
    return (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3));
}
uint32_t  sigma1(uint32_t x) {
    return (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10));
}


int sha256Init(t_sha256_ctx *ctx) {
    memset(ctx, 0, sizeof(t_sha256_ctx));
    memcpy(ctx->state, g_sha256, sizeof(g_sha256));
    memcpy(ctx->sha256const, g_sha256const, sizeof(g_sha256const));
    return 0;
}


void sha256Pad(t_sha256_ctx *ctx) {
    unsigned char *buffer = ctx->buffer;
    uint64_t input_len = ctx->bytelen;

    //log_debug("Padding SHA256 with %zu bits of data", ctx->bitlen);
    if (ctx->bitlen == 512) {
        sha256Compression(ctx);
        ctx->bitlen = 0;
    }

    size_t zeros = (447 - ctx->bitlen) % 512;
    buffer[ctx->bitlen / 8] = 0x80;
    ctx->bitlen += 8;

    for (size_t i = 0; i < (zeros - 7) / 8; i++) {
        if (ctx->bitlen == 512) {
            sha256Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[(ctx->bitlen / 8)] = 0x00;
        ctx->bitlen += 8;
    }

    for (size_t i = 0; i < 8; i++) {
        if (ctx->bitlen == 512) {
            sha256Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[ctx->bitlen / 8] = input_len >> ((7 - i) * 8);
        ctx->bitlen += 8;
    }
    sha256Compression(ctx);
}

void sha256Update(t_sha256_ctx *ctx, const unsigned char *data, size_t len){
#ifdef DEBUG
    log_info("%s", (len * 8 > 512 - ctx->bitlen) ? "Chunking data into 64-byte blocks" : "Data fits in a single block");
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
        
#ifdef DEBUG
        log_debug("Current offset: %zu", offset * 8);
#endif
        sha256Compression(ctx);
        ctx->bitlen = 0;
    }

    memcpy(&ctx->buffer[ctx->bitlen / 8], &data[offset], len - offset);
    ctx->bitlen += (len - offset) * 8;
}

// Big endian
uint32_t constructBlockBE(const unsigned char *buffer) {
    uint32_t block;
    memset(&block, 0, sizeof(block));
    for (size_t i = 0; i < 4; i++){
        block |= (uint32_t)buffer[i] << ((3 - i) * 8);
    }
    return block;
}

void sha256Compression(t_sha256_ctx *ctx) {
    uint32_t M[64];

    memset(M, 0, sizeof(M));
    // Breaking our ctx->buffer into 64 32 bit words (4 bytes need to be combinted into 1 word)
    size_t i = 0;
    for (; i < 16; i++) {
        M[i] = constructBlockBE(&ctx->buffer[i * 4]);
    }
    for (; i < 64; i++) {
        M[i] = sigma1(M[i - 2]) + M[i - 7] + sigma0(M[i - 15]) + M[i - 16];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (size_t j = 0; j < 64; j++) {
        uint32_t    T1 = h + Sigma1(e) + Ch(e, f, g) + ctx->sha256const[j] + M[j];
        uint32_t    T2 = Sigma0(a) + Maj(a, b, c);
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

void sha256(const char *input, size_t len, const char *label, bool is_string, const t_options options, bool is_file)
{
    t_sha256_ctx ctx;
    sha256Init(&ctx);
    sha256Update(&ctx, (const unsigned char *)input, strlen(input));
    sha256Pad(&ctx);
    for (size_t i = 0; i < 8; i++) {
        snprintf(&ctx.sha256rslt[i * 8], 9, "%08x", ctx.state[i]);
    }
    printHash("SHA256", ctx.sha256rslt, is_string, options, is_file, label);
}