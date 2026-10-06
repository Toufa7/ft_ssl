#include "../include/ft_sha1.h"


static const uint32_t g_sha1[5] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0
};
/*
    2,3,5,10 => (x^(1÷2))÷4
*/
static const uint32_t g_sha1const[4] = {
    0x5a827999,
    0x6ed9eba1,
    0x8f1bbcdc,
    0xca62c1d6,
};


u_int32_t SHA1roundF(uint32_t x, uint32_t y, uint32_t z){
    return (x & y) | ((~x) & z);
}
u_int32_t SHA1roundG(uint32_t x, uint32_t y, uint32_t z){
    return (x ^ y ^ z);
}
u_int32_t SHA1roundH(uint32_t x, uint32_t y, uint32_t z){
    return (x & y) | (x & z) | (y & z);
}
u_int32_t SHA1roundI(uint32_t x, uint32_t y, uint32_t z){
    return (x ^ y ^ z);
}

int sha1Init(t_sha1_ctx *ctx) {
    memset(ctx, 0, sizeof(t_sha1_ctx));
    memcpy(ctx->state, g_sha1, sizeof(g_sha1));
    return 0;
}

void sha1Pad(t_sha1_ctx *ctx) {
    unsigned char *buffer = ctx->buffer;
    uint64_t input_len = ctx->bytelen;

    if (ctx->bitlen == 512) {
        sha1Compression(ctx);
        ctx->bitlen = 0;
    }

    size_t zeros = (447 - ctx->bitlen) % 512;
    buffer[ctx->bitlen / 8] = 0x80;
    ctx->bitlen += 8;

    for (size_t i = 0; i < (zeros - 7) / 8; i++) {
        if (ctx->bitlen == 512) {
            sha1Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[(ctx->bitlen / 8)] = 0x00;
        ctx->bitlen += 8;
    }

    for (size_t i = 0; i < 8; i++) {
        if (ctx->bitlen == 512) {
            sha1Compression(ctx);
            ctx->bitlen = 0;
        }
        buffer[ctx->bitlen / 8] = input_len >> ((7 - i) * 8);
        ctx->bitlen += 8;
    }
    sha1Compression(ctx);
}

void sha1Update(t_sha1_ctx *ctx, const unsigned char *data, size_t len){
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
        sha1Compression(ctx);
        ctx->bitlen = 0;
    }

    memcpy(&ctx->buffer[ctx->bitlen / 8], &data[offset], len - offset);
    ctx->bitlen += (len - offset) * 8;
}

void sha1Compression(t_sha1_ctx *ctx) {
    uint32_t W[80];
    memset(W, 0, sizeof(W));
    size_t i = 0;
    for (; i < 16; i++) {
        W[i] = constructBlockBE(&ctx->buffer[i * 4]);
    }
    for (; i < 80; i++) {
        W[i] = ROTL((W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]), 1);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = SHA1roundF(b, c, d);
            k = g_sha1const[0];
        } else if (i < 40) {
            f = SHA1roundG(b, c, d);
            k = g_sha1const[1];
        } else if (i < 60) {
            f = SHA1roundH(b, c, d);
            k = g_sha1const[2];
        } else {
            f = SHA1roundI(b, c, d);
            k = g_sha1const[3];
        }
        uint32_t temp = ROTL(a, 5) + f + e + k + W[i];
        e = d;
        d = c;
        c = ROTL(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1(const char *input, size_t len, const char *label, bool is_string, const t_options options, bool is_file){
    t_sha1_ctx ctx;
    sha1Init(&ctx);
    sha1Update(&ctx, (const unsigned char *)input, len);
    sha1Pad(&ctx);

    size_t pos = 0;
    for (size_t i = 0; i < 5; i++) {
        uint32_t word = ctx.state[i];
        for (size_t j = 0; j < 4; j++) {
            pos += sprintf(&ctx.sha1rslt[pos],"%02x", (word >> ((3 - j) * 8)) & 0xFF);
        }
    }
    printHash("SHA1", ctx.sha1rslt, is_string, options, is_file, label);

}

