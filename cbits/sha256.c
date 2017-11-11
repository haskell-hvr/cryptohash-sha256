/*
 * Copyright (C) 2006-2009 Vincent Hanquez <vincent@snarc.org>
 *               2016      Herbert Valerio Riedel <hvr@gnu.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "sha256.h"

#include <assert.h>
#include <string.h>
#include <ghcautoconf.h>

#if defined(static_assert)
static_assert(sizeof(struct sha256_ctx) == SHA256_CTX_SIZE, "unexpected sha256_ctx size");
#else
/* poor man's pre-C11 _Static_assert */
typedef char static_assertion__unexpected_sha256_ctx_size[(sizeof(struct sha256_ctx) == SHA256_CTX_SIZE)?1:-1];
#endif

#define ptr_uint32_aligned(ptr) (!((uintptr_t)(ptr) & 0x3))

static inline uint32_t
ror32(const uint32_t word, const unsigned shift)
{
  /* GCC usually transforms this into a 'ror'-insn */
  return (word >> shift) | (word << (32 - shift));
}

static inline uint32_t
cpu_to_be32(const uint32_t hl)
{
#if WORDS_BIGENDIAN
  return hl;
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
  return __builtin_bswap32(hl);
#else
  /* GCC usually transforms this into a bswap insn */
  return ((hl & 0xff000000) >> 24) |
         ((hl & 0x00ff0000) >> 8)  |
         ((hl & 0x0000ff00) << 8)  |
         ( hl               << 24);
#endif
}

static inline void
cpu_to_be32_array(uint32_t *dest, const uint32_t *src, unsigned wordcnt)
{
  while (wordcnt--)
    *dest++ = cpu_to_be32(*src++);
}

static inline uint64_t
cpu_to_be64(const uint64_t hll)
{
#if WORDS_BIGENDIAN
  return hll;
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
  return __builtin_bswap64(hll);
#else
  return ((uint64_t)cpu_to_be32(hll & 0xffffffff) << 32LL) | cpu_to_be32(hll >> 32);
#endif
}


void
hs_cryptohash_sha256_init (struct sha256_ctx *ctx)
{
  memset(ctx, 0, SHA256_CTX_SIZE);

  ctx->h[0] = 0x6a09e667;
  ctx->h[1] = 0xbb67ae85;
  ctx->h[2] = 0x3c6ef372;
  ctx->h[3] = 0xa54ff53a;
  ctx->h[4] = 0x510e527f;
  ctx->h[5] = 0x9b05688c;
  ctx->h[6] = 0x1f83d9ab;
  ctx->h[7] = 0x5be0cd19;
}

/* 232 times the cube root of the first 64 primes 2..311 */
static const uint32_t k[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define e0(x)       (ror32(x, 2) ^ ror32(x,13) ^ ror32(x,22))
#define e1(x)       (ror32(x, 6) ^ ror32(x,11) ^ ror32(x,25))
#define s0(x)       (ror32(x, 7) ^ ror32(x,18) ^ (x >> 3))
#define s1(x)       (ror32(x,17) ^ ror32(x,19) ^ (x >> 10))

static void
sha256_do_chunk_aligned(struct sha256_ctx *ctx, uint32_t w[])
{
  int i;

  for (i = 16; i < 64; i++)
    w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];

  uint32_t a = ctx->h[0];
  uint32_t b = ctx->h[1];
  uint32_t c = ctx->h[2];
  uint32_t d = ctx->h[3];
  uint32_t e = ctx->h[4];
  uint32_t f = ctx->h[5];
  uint32_t g = ctx->h[6];
  uint32_t h = ctx->h[7];

#define R(a, b, c, d, e, f, g, h, k, w)             \
    t1 = h + e1(e) + (g ^ (e & (f ^ g))) + k + w;   \
    t2 = e0(a) + ((a & b) | (c & (a | b)));         \
    d += t1;                                        \
    h = t1 + t2;

  for (i = 0; i < 64; i += 8) {
    uint32_t t1, t2;

    R(a, b, c, d, e, f, g, h, k[i + 0], w[i + 0]);
    R(h, a, b, c, d, e, f, g, k[i + 1], w[i + 1]);
    R(g, h, a, b, c, d, e, f, k[i + 2], w[i + 2]);
    R(f, g, h, a, b, c, d, e, k[i + 3], w[i + 3]);
    R(e, f, g, h, a, b, c, d, k[i + 4], w[i + 4]);
    R(d, e, f, g, h, a, b, c, k[i + 5], w[i + 5]);
    R(c, d, e, f, g, h, a, b, k[i + 6], w[i + 6]);
    R(b, c, d, e, f, g, h, a, k[i + 7], w[i + 7]);
  }

#undef R

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
  ctx->h[5] += f;
  ctx->h[6] += g;
  ctx->h[7] += h;
}

static void
sha256_do_chunk(struct sha256_ctx *ctx, const uint8_t buf[])
{
  uint32_t w[64]; /* only first 16 words are filled in */
  if (ptr_uint32_aligned(buf)) { /* aligned buf */
    cpu_to_be32_array(w, (const uint32_t *)buf, 16);
  } else { /* unaligned buf */
    memcpy(w, buf, 64);
#if !WORDS_BIGENDIAN
    cpu_to_be32_array(w, w, 16);
#endif
  }
  sha256_do_chunk_aligned(ctx, w);
}

void
hs_cryptohash_sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len)
{
  size_t index = ctx->sz & 0x3f;
  const size_t to_fill = 64 - index;

  ctx->sz += len;

  /* process partial buffer if there's enough data to make a block */
  if (index && len >= to_fill) {
    memcpy(ctx->buf + index, data, to_fill);
    sha256_do_chunk(ctx, ctx->buf);
    /* memset(ctx->buf, 0, 64); */
    len -= to_fill;
    data += to_fill;
    index = 0;
  }

  /* process as many 64-blocks as possible */
  while (len >= 64) {
    sha256_do_chunk(ctx, data);
    len -= 64;
    data += 64;
  }

  /* append data into buf */
  if (len)
    memcpy(ctx->buf + index, data, len);
}

uint64_t
hs_cryptohash_sha256_finalize (struct sha256_ctx *ctx, uint8_t *out)
{
  static const uint8_t padding[64] = { 0x80, };
  const uint64_t sz = ctx->sz;

  /* add padding and update data with it */
  uint64_t bits = cpu_to_be64(ctx->sz << 3);

  /* pad out to 56 */
  const size_t index = ctx->sz & 0x3f;
  const size_t padlen = (index < 56) ? (56 - index) : ((64 + 56) - index);
  hs_cryptohash_sha256_update(ctx, padding, padlen);

  /* append length */
  hs_cryptohash_sha256_update(ctx, (uint8_t *) &bits, sizeof(bits));

  /* output hash */
  cpu_to_be32_array((uint32_t *) out, ctx->h, 8);

  return sz;
}
