/*
 * Copyright (c) 2015, Cameron Rich
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, 
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice, 
 *   this list of conditions and the following disclaimer in the documentation 
 *   and/or other materials provided with the distribution.
 * * Neither the name of the axTLS project nor the names of its contributors 
 *   may be used to endorse or promote products derived from this software 
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include "os_port.h"
#include "crypto.h"

#ifndef SHA256_CTX

#define GET_UINT32(n,b,i)                       \
{                                               \
    (n) = ((uint32_t) (b)[(i)    ] << 24)       \
        | ((uint32_t) (b)[(i) + 1] << 16)       \
        | ((uint32_t) (b)[(i) + 2] <<  8)       \
        | ((uint32_t) (b)[(i) + 3]      );      \
}

#define PUT_UINT32(n,b,i)                       \
{                                               \
    (b)[(i)    ] = (uint8_t) ((n) >> 24);       \
    (b)[(i) + 1] = (uint8_t) ((n) >> 16);       \
    (b)[(i) + 2] = (uint8_t) ((n) >>  8);       \
    (b)[(i) + 3] = (uint8_t) ((n)      );       \
}

static const uint8_t sha256_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * Initialize the SHA256 context 
 */
void SHA256_Init(SHA256_CTX *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}

static void SHA256_Process(const uint8_t digest[64], SHA256_CTX *ctx)
{
#ifndef CONFIG_M68K_ASM
    uint32_t temp1, temp2, W[64];
    uint32_t A, B, C, D, E, F, G, H;

    GET_UINT32(W[0],  digest,  0);
    GET_UINT32(W[1],  digest,  4);
    GET_UINT32(W[2],  digest,  8);
    GET_UINT32(W[3],  digest, 12);
    GET_UINT32(W[4],  digest, 16);
    GET_UINT32(W[5],  digest, 20);
    GET_UINT32(W[6],  digest, 24);
    GET_UINT32(W[7],  digest, 28);
    GET_UINT32(W[8],  digest, 32);
    GET_UINT32(W[9],  digest, 36);
    GET_UINT32(W[10], digest, 40);
    GET_UINT32(W[11], digest, 44);
    GET_UINT32(W[12], digest, 48);
    GET_UINT32(W[13], digest, 52);
    GET_UINT32(W[14], digest, 56);
    GET_UINT32(W[15], digest, 60);

#define  SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                              \
    W[t] = S1(W[t -  2]) + W[t -  7] +          \
           S0(W[t - 15]) + W[t - 16]            \
)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    P(A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98);
    P(H, A, B, C, D, E, F, G, W[ 1], 0x71374491);
    P(G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF);
    P(F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5);
    P(E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B);
    P(D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1);
    P(C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4);
    P(B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5);
    P(A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98);
    P(H, A, B, C, D, E, F, G, W[ 9], 0x12835B01);
    P(G, H, A, B, C, D, E, F, W[10], 0x243185BE);
    P(F, G, H, A, B, C, D, E, W[11], 0x550C7DC3);
    P(E, F, G, H, A, B, C, D, W[12], 0x72BE5D74);
    P(D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE);
    P(C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7);
    P(B, C, D, E, F, G, H, A, W[15], 0xC19BF174);
    P(A, B, C, D, E, F, G, H, R(16), 0xE49B69C1);
    P(H, A, B, C, D, E, F, G, R(17), 0xEFBE4786);
    P(G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6);
    P(F, G, H, A, B, C, D, E, R(19), 0x240CA1CC);
    P(E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F);
    P(D, E, F, G, H, A, B, C, R(21), 0x4A7484AA);
    P(C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC);
    P(B, C, D, E, F, G, H, A, R(23), 0x76F988DA);
    P(A, B, C, D, E, F, G, H, R(24), 0x983E5152);
    P(H, A, B, C, D, E, F, G, R(25), 0xA831C66D);
    P(G, H, A, B, C, D, E, F, R(26), 0xB00327C8);
    P(F, G, H, A, B, C, D, E, R(27), 0xBF597FC7);
    P(E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3);
    P(D, E, F, G, H, A, B, C, R(29), 0xD5A79147);
    P(C, D, E, F, G, H, A, B, R(30), 0x06CA6351);
    P(B, C, D, E, F, G, H, A, R(31), 0x14292967);
    P(A, B, C, D, E, F, G, H, R(32), 0x27B70A85);
    P(H, A, B, C, D, E, F, G, R(33), 0x2E1B2138);
    P(G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC);
    P(F, G, H, A, B, C, D, E, R(35), 0x53380D13);
    P(E, F, G, H, A, B, C, D, R(36), 0x650A7354);
    P(D, E, F, G, H, A, B, C, R(37), 0x766A0ABB);
    P(C, D, E, F, G, H, A, B, R(38), 0x81C2C92E);
    P(B, C, D, E, F, G, H, A, R(39), 0x92722C85);
    P(A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1);
    P(H, A, B, C, D, E, F, G, R(41), 0xA81A664B);
    P(G, H, A, B, C, D, E, F, R(42), 0xC24B8B70);
    P(F, G, H, A, B, C, D, E, R(43), 0xC76C51A3);
    P(E, F, G, H, A, B, C, D, R(44), 0xD192E819);
    P(D, E, F, G, H, A, B, C, R(45), 0xD6990624);
    P(C, D, E, F, G, H, A, B, R(46), 0xF40E3585);
    P(B, C, D, E, F, G, H, A, R(47), 0x106AA070);
    P(A, B, C, D, E, F, G, H, R(48), 0x19A4C116);
    P(H, A, B, C, D, E, F, G, R(49), 0x1E376C08);
    P(G, H, A, B, C, D, E, F, R(50), 0x2748774C);
    P(F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5);
    P(E, F, G, H, A, B, C, D, R(52), 0x391C0CB3);
    P(D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A);
    P(C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F);
    P(B, C, D, E, F, G, H, A, R(55), 0x682E6FF3);
    P(A, B, C, D, E, F, G, H, R(56), 0x748F82EE);
    P(H, A, B, C, D, E, F, G, R(57), 0x78A5636F);
    P(G, H, A, B, C, D, E, F, R(58), 0x84C87814);
    P(F, G, H, A, B, C, D, E, R(59), 0x8CC70208);
    P(E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA);
    P(D, E, F, G, H, A, B, C, R(61), 0xA4506CEB);
    P(C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7);
    P(B, C, D, E, F, G, H, A, R(63), 0xC67178F2);

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
#else
    uint32_t W[64];

    memcpy(W, digest, 64);  // for big endian

#define S0a(r, x, t1, t2)   \
    "move.l  " x "," r "\n"                                         \
    "ror.l   #7," r "\n"        /* ROTR(x,7) */                     \
    "move.l  " r "," t1 "\n"                                        \
    "moveq.l #11," t2 "\n"                                          \
    "ror.l   " t2 "," t1 "\n"   /* ROTR(x,18 = 7+11) */             \
    "eor.l   " t1 "," r "\n"    /* r = ROTR(x,7) ^ ROTR(x,18) */    \
    "move.l  " x "," t1 "\n"                                        \
    "lsr.l   #3," t1 "\n"       /* SHR(x,3) */                      \
    "eor.l   " t1 "," r "\n"    /* r = ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3) */

#define S1a(r, x, t1, t2)   \
    "move.l  " x "," r "\n"                                         \
    "swap    " r "\n"                                               \
    "ror.l   #1," r "\n"        /* ROTR(x,17 = 16+1) */             \
    "move.l  " r "," t1 "\n"                                        \
    "ror.l   #2," t1 "\n"       /* ROTR(x,19 = 17+2) */             \
    "eor.l   " t1 "," r "\n"    /* r = ROTR(x,17) ^ ROTR(x,19) */   \
    "move.l  " x "," t1 "\n"                                        \
    "moveq.l #10," t2 "\n"                                          \
    "lsr.l   " t2 "," t1 "\n"   /* SHR(x,10) */                     \
    "eor.l   " t1 "," r "\n"    /* r = ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10) */

#define S2a(r, x, t1, t2)   \
    "move.l  " x "," r "\n"                                         \
    "ror.l   #2," r "\n"        /* ROTR(x,2) */                     \
    "move.l  " r "," t1 "\n"                                        \
    "moveq.l #11," t2 "\n"                                          \
    "ror.l   " t2 "," t1 "\n"   /* ROTR(x,13 = 2+11) */             \
    "eor.l   " t1 "," r "\n"    /* r = ROTR(x,2) ^ ROTR(x,13) */    \
    "move.l  " x "," t1 "\n"                                        \
    "moveq.l #10," t2 "\n"                                          \
    "rol.l   " t2 "," t1 "\n"   /* ROTR(x,22) = ROTL(x,10) */       \
    "eor.l   " t1 "," r "\n"    /* r = ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22) */

#define S3a(r, x, t1)   \
    "move.l  " x "," r "\n"                                         \
    "ror.l   #6," r "\n"        /* ROTR(x,6) */                     \
    "move.l  " r "," t1 "\n"                                        \
    "ror.l   #5," t1 "\n"       /* ROTR(x,11 = 6+5) */              \
    "eor.l   " t1 "," r "\n"    /* r = ROTR(x,6) ^ ROTR(x,11) */    \
    "move.l  " x "," t1 "\n"                                        \
    "rol.l   #7," t1 "\n"        /* ROTR(x,25) = ROTL(x,7) */       \
    "eor.l   " t1 "," r "\n"    /* r = ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25) */

#define F0a(r, x, y, z, t1)   \
    "move.l  " x "," r "\n"                                         \
    "or.l    " y "," r "\n"     /* x | y */                         \
    "and.l   " z "," r "\n"     /* z & (x | y) */                   \
    "move.l  " x "," t1 "\n"                                        \
    "and.l   " y "," t1 "\n"    /* x & y */                         \
    "or.l    " t1 "," r "\n"    /* (x & y) | (z & (x | y)) */

#define F1a(r, x, y, z, t1)   \
    "move.l  " y "," r "\n"                                         \
    "move.l  " z "," t1 "\n"                                        \
    "eor.l   " t1 "," r "\n"    /* y ^ z */                         \
    "and.l   " x "," r "\n"     /* x & (y ^ z) */                   \
    "eor.l   " t1 "," r "\n"    /* z ^ (x & (y ^ z)) */

#define Ra(r, W, t, t1, t2, t3) \
    S1a(r, W "@((" #t "-2)*4)", t1, t2)     /* S1(W[t-2]) */        \
    "add.l   " W "@((" #t "-7)*4)," r "\n"  /* + W[t-7] */          \
    S0a(t3, W "@((" #t "-15)*4)", t1, t2)   /* + S0(W[t-15]) */     \
    "add.l   " t3 "," r "\n"                                        \
    "add.l   " W "@((" #t "-16)*4)," r "\n" /* r = S1(W[t-2]) + W[t-7] + S0(W[t-15]) + W[t-16] */ \
    "move.l  " r "," W "@(" #t "*4)\n"      /* W[t] = r */

#define Temp1a(r, e, f, g, h, x, K, t1, t2)   \
    S3a(t1, e, r)               /* t1 = S3(e) */                    \
    "move.l  " x "," r "\n"                                         \
    "addi.l  #" #K "," r "\n"                                       \
    "add.l   " h "," r "\n"     /* r = h + K + x */                 \
    "add.l   " r "," t1 "\n"    /* tt = h + S3(e)) + K + x */       \
    F1a(r, e, f, g, t2)                                             \
    "add.l   " t1 "," r "\n"    /* r = h + S3(e) + F1(e,f,g) + K + x */

#define Temp2a(r, a, b, c, t1, t2) \
    S2a(t1, a, t2, r)           /* t1 = S2(a) */                    \
    F0a(r, a, b, c, t2)         /* r = F0(a,b,c) */                 \
    "add.l   " t1 "," r "\n"    /* r = S2(a) + F0(a,b,c) */

#define Pa(a, b, c, d, e, f, g, h, x, K, t1, t2, t3) \
    "move.l  " a "," t1 "\n"                                        \
    "move.l  " b "," t2 "\n"                                        \
    "move.l  " c "," t3 "\n"                                        \
    Temp1a(a, e, f, g, h, x, K, b, c)                               \
    "move.l  " a "," h "\n"    /* h = temp1 */                      \
    "add.l   " a "," d "\n"    /* d += temp1 */                     \
    "move.l  " t1 "," a "\n"                                        \
    "move.l  " t2 "," b "\n"                                        \
    "move.l  " t3 "," c "\n"                                        \
    \
    "move.l  " d "," t1 "\n"                                        \
    "move.l  " e "," t2 "\n"                                        \
    "move.l  " f "," t3 "\n"                                        \
    Temp2a(f, a, b, c, d, e)                                        \
    "add.l   " f "," h "\n"    /* h = temp1 + temp2 */              \
    "move.l  " t1 "," d "\n"                                        \
    "move.l  " t2 "," e "\n"                                        \
    "move.l  " t3 "," f "\n"

#define Pb(a, b, c, d, e, f, g, h, x, t, K, t1, t2, t3, t4) \
    "move.l  " a "," t1 "\n"                                        \
    "move.l  " b "," t2 "\n"                                        \
    "move.l  " c "," t3 "\n"                                        \
    "move.l  " d "," t4 "\n"                                        \
    Ra(b, x, t, a, c, d)                                            \
    Temp1a(a, e, f, g, h, b, K, c, d)                               \
    "move.l  " t4 "," d "\n"                                        \
    "move.l  " a "," h "\n"    /* h = temp1 */                      \
    "add.l   " a "," d "\n"    /* d += temp1 */                     \
    "move.l  " t1 "," a "\n"                                        \
    "move.l  " t2 "," b "\n"                                        \
    "move.l  " t3 "," c "\n"                                        \
    \
    "move.l  " d "," t1 "\n"                                        \
    "move.l  " e "," t2 "\n"                                        \
    "move.l  " f "," t3 "\n"                                        \
    Temp2a(f, a, b, c, d, e)                                        \
    "add.l   " f "," h "\n"    /* h = temp1 + temp2 */              \
    "move.l  " t1 "," d "\n"                                        \
    "move.l  " t2 "," e "\n"                                        \
    "move.l  " t3 "," f "\n"

#define Px(a, b, c, d, e, f, g, h, t, K) \
    Pa("%%d"#a, "%%d"#b, "%%d"#c, "%%d"#d, "%%d"#e, "%%d"#f, "%%d"#g, "%%d"#h, \
        "%1@("#t"*4)", K, "%%a0", "%%a1", "%%a2")

#define Py(a, b, c, d, e, f, g, h, t, K) \
    Pb("%%d"#a, "%%d"#b, "%%d"#c, "%%d"#d, "%%d"#e, "%%d"#f, "%%d"#g, "%%d"#h, \
        "%1", t, K, "%%a0", "%%a1", "%%a2", "%%a3")

    __asm__ volatile(
        "nop\n"
        "movem.l %0@,%%d0-%%d7\n"

        Px(0, 1, 2, 3, 4, 5, 6, 7,  0, 0x428A2F98)
        Px(7, 0, 1, 2, 3, 4, 5, 6,  1, 0x71374491)
        Px(6, 7, 0, 1, 2, 3, 4, 5,  2, 0xB5C0FBCF)
        Px(5, 6, 7, 0, 1, 2, 3, 4,  3, 0xE9B5DBA5)
        Px(4, 5, 6, 7, 0, 1, 2, 3,  4, 0x3956C25B)
        Px(3, 4, 5, 6, 7, 0, 1, 2,  5, 0x59F111F1)
        Px(2, 3, 4, 5, 6, 7, 0, 1,  6, 0x923F82A4)
        Px(1, 2, 3, 4, 5, 6, 7, 0,  7, 0xAB1C5ED5)
        Px(0, 1, 2, 3, 4, 5, 6, 7,  8, 0xD807AA98)
        Px(7, 0, 1, 2, 3, 4, 5, 6,  9, 0x12835B01)
        Px(6, 7, 0, 1, 2, 3, 4, 5, 10, 0x243185BE)
        Px(5, 6, 7, 0, 1, 2, 3, 4, 11, 0x550C7DC3)
        Px(4, 5, 6, 7, 0, 1, 2, 3, 12, 0x72BE5D74)
        Px(3, 4, 5, 6, 7, 0, 1, 2, 13, 0x80DEB1FE)
        Px(2, 3, 4, 5, 6, 7, 0, 1, 14, 0x9BDC06A7)
        Px(1, 2, 3, 4, 5, 6, 7, 0, 15, 0xC19BF174)
        Py(0, 1, 2, 3, 4, 5, 6, 7, 16, 0xE49B69C1)
        Py(7, 0, 1, 2, 3, 4, 5, 6, 17, 0xEFBE4786)
        Py(6, 7, 0, 1, 2, 3, 4, 5, 18, 0x0FC19DC6)
        Py(5, 6, 7, 0, 1, 2, 3, 4, 19, 0x240CA1CC)
        Py(4, 5, 6, 7, 0, 1, 2, 3, 20, 0x2DE92C6F)
        Py(3, 4, 5, 6, 7, 0, 1, 2, 21, 0x4A7484AA)
        Py(2, 3, 4, 5, 6, 7, 0, 1, 22, 0x5CB0A9DC)
        Py(1, 2, 3, 4, 5, 6, 7, 0, 23, 0x76F988DA)
        Py(0, 1, 2, 3, 4, 5, 6, 7, 24, 0x983E5152)
        Py(7, 0, 1, 2, 3, 4, 5, 6, 25, 0xA831C66D)
        Py(6, 7, 0, 1, 2, 3, 4, 5, 26, 0xB00327C8)
        Py(5, 6, 7, 0, 1, 2, 3, 4, 27, 0xBF597FC7)
        Py(4, 5, 6, 7, 0, 1, 2, 3, 28, 0xC6E00BF3)
        Py(3, 4, 5, 6, 7, 0, 1, 2, 29, 0xD5A79147)
        Py(2, 3, 4, 5, 6, 7, 0, 1, 30, 0x06CA6351)
        Py(1, 2, 3, 4, 5, 6, 7, 0, 31, 0x14292967)
        Py(0, 1, 2, 3, 4, 5, 6, 7, 32, 0x27B70A85)
        Py(7, 0, 1, 2, 3, 4, 5, 6, 33, 0x2E1B2138)
        Py(6, 7, 0, 1, 2, 3, 4, 5, 34, 0x4D2C6DFC)
        Py(5, 6, 7, 0, 1, 2, 3, 4, 35, 0x53380D13)
        Py(4, 5, 6, 7, 0, 1, 2, 3, 36, 0x650A7354)
        Py(3, 4, 5, 6, 7, 0, 1, 2, 37, 0x766A0ABB)
        Py(2, 3, 4, 5, 6, 7, 0, 1, 38, 0x81C2C92E)
        Py(1, 2, 3, 4, 5, 6, 7, 0, 39, 0x92722C85)
        Py(0, 1, 2, 3, 4, 5, 6, 7, 40, 0xA2BFE8A1)
        Py(7, 0, 1, 2, 3, 4, 5, 6, 41, 0xA81A664B)
        Py(6, 7, 0, 1, 2, 3, 4, 5, 42, 0xC24B8B70)
        Py(5, 6, 7, 0, 1, 2, 3, 4, 43, 0xC76C51A3)
        Py(4, 5, 6, 7, 0, 1, 2, 3, 44, 0xD192E819)
        Py(3, 4, 5, 6, 7, 0, 1, 2, 45, 0xD6990624)
        Py(2, 3, 4, 5, 6, 7, 0, 1, 46, 0xF40E3585)
        Py(1, 2, 3, 4, 5, 6, 7, 0, 47, 0x106AA070)
        Py(0, 1, 2, 3, 4, 5, 6, 7, 48, 0x19A4C116)
        Py(7, 0, 1, 2, 3, 4, 5, 6, 49, 0x1E376C08)
        Py(6, 7, 0, 1, 2, 3, 4, 5, 50, 0x2748774C)
        Py(5, 6, 7, 0, 1, 2, 3, 4, 51, 0x34B0BCB5)
        Py(4, 5, 6, 7, 0, 1, 2, 3, 52, 0x391C0CB3)
        Py(3, 4, 5, 6, 7, 0, 1, 2, 53, 0x4ED8AA4A)
        Py(2, 3, 4, 5, 6, 7, 0, 1, 54, 0x5B9CCA4F)
        Py(1, 2, 3, 4, 5, 6, 7, 0, 55, 0x682E6FF3)
        Py(0, 1, 2, 3, 4, 5, 6, 7, 56, 0x748F82EE)
        Py(7, 0, 1, 2, 3, 4, 5, 6, 57, 0x78A5636F)
        Py(6, 7, 0, 1, 2, 3, 4, 5, 58, 0x84C87814)
        Py(5, 6, 7, 0, 1, 2, 3, 4, 59, 0x8CC70208)
        Py(4, 5, 6, 7, 0, 1, 2, 3, 60, 0x90BEFFFA)
        Py(3, 4, 5, 6, 7, 0, 1, 2, 61, 0xA4506CEB)
        Py(2, 3, 4, 5, 6, 7, 0, 1, 62, 0xBEF9A3F7)
        Py(1, 2, 3, 4, 5, 6, 7, 0, 63, 0xC67178F2)

        "movea.l %0,%%a0\n"
        "add.l %%d0,%%a0@+\n"
        "add.l %%d1,%%a0@+\n"
        "add.l %%d2,%%a0@+\n"
        "add.l %%d3,%%a0@+\n"
        "add.l %%d4,%%a0@+\n"
        "add.l %%d5,%%a0@+\n"
        "add.l %%d6,%%a0@+\n"
        "add.l %%d7,%%a0@+\n"
        "nop\n"
        : : "a"(ctx->state), "a"(W)
        : "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "a0", "a1", "a2", "a3", "cc", "memory"
    );
#endif
}

/**
 * Accepts an array of octets as the next portion of the message.
 */
void SHA256_Update(SHA256_CTX *ctx, const uint8_t * msg, int len)
{
    uint32_t left = ctx->total[0] & 0x3F;
    uint32_t fill = 64 - left;

    ctx->total[0] += len;
    ctx->total[0] &= 0xFFFFFFFF;

    if (ctx->total[0] < len)
        ctx->total[1]++;

    if (left && len >= fill)
    {
        memcpy((void *) (ctx->buffer + left), (void *)msg, fill);
        SHA256_Process(ctx->buffer, ctx);
        len -= fill;
        msg  += fill;
        left = 0;
    }

    while (len >= 64)
    {
        SHA256_Process(msg, ctx);
        len -= 64;
        msg  += 64;
    }

    if (len)
    {
        memcpy((void *) (ctx->buffer + left), (void *) msg, len);
    }
}

/**
 * Return the 256-bit message digest into the user's array
 */
void SHA256_Final(uint8_t *digest, SHA256_CTX *ctx)
{
    uint32_t last, padn;
    uint32_t high, low;
    uint8_t msglen[8];

    high = (ctx->total[0] >> 29)
         | (ctx->total[1] <<  3);
    low  = (ctx->total[0] <<  3);

    PUT_UINT32(high, msglen, 0);
    PUT_UINT32(low,  msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    SHA256_Update(ctx, sha256_padding, padn);
    SHA256_Update(ctx, msglen, 8);

#ifndef CONFIG_M68K_ASM
    PUT_UINT32(ctx->state[0], digest,  0);
    PUT_UINT32(ctx->state[1], digest,  4);
    PUT_UINT32(ctx->state[2], digest,  8);
    PUT_UINT32(ctx->state[3], digest, 12);
    PUT_UINT32(ctx->state[4], digest, 16);
    PUT_UINT32(ctx->state[5], digest, 20);
    PUT_UINT32(ctx->state[6], digest, 24);
    PUT_UINT32(ctx->state[7], digest, 28);
#else
    memcpy(digest, ctx->state, 32);  // for big endian
#endif
}

#endif // SHA256_CTX
