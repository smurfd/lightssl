#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lightdefs.h"

typedef struct pt {u64 x[DI], y[DI];} pt;

static u64 curve_p[DI] = {
  0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe,
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static u64 curve_b[DI] = {
  0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a,
  0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4};
static pt curve_g      = {{
  0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38,
  0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74, 0xaa87ca22be8b0537},
  {0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0,
  0xf8f41dbd289a147c, 0x5d9e98bf9292dc29, 0x3617de4a96262c6f}};
static u64 curve_n[DI] = {
  0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf,
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};

typedef struct {u64 a, b, c, d;} prng_t;
static prng_t prng_ctx;

// Random
u64 prng_rotate(u64 x, u64 k);
u64 prng_next(void);
void prng_init(u64 seed);

int keys_make_keys(u64 publ[KB + 1], u64 priv[KB]);
int keys_shar_secr(const u64 publ[KB + 1], const u64 priv[KB], u64 secr[KB]);
int keys_sign(const u64 priv[KB], const u64 hash[KB], u64 sign[KB2]);
int keys_vrfy(const u64 publ[KB + 1], const u64 hash[KB], const u64 sign[KB2]);
#endif
