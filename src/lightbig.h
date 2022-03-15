//                                                                            //
#ifndef LIGHTBIG_H
#define LIGHTBIG_H 1

#include <stdbool.h>

#define MAXSTR 512
#define BIGLEN 1024
#define DEC 10
#define HEX 16

typedef struct {
  int *dig;
  int len;
  int base;
  bool neg;
  bool alloc_t;
  bool alloc_d;
} bigint_t;

// Init
char *big_get(const bigint_t *a);
void big_get_2(const bigint_t *a, char *b);
void big_init(bigint_t **a);
void big_end(bigint_t **a);
void big_set(char *a, bigint_t **b);
void big_set_2(char *a, bigint_t **b);
void big_clear_zero(bigint_t **b);
void big_clear_zero2(bigint_t **b);
void big_clear_zeros(bigint_t **b);

// Operations
void big_add(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_add_2(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_mul(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_mul_2(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_sub(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_sub_2(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_mod(const bigint_t *a, const bigint_t *b, bigint_t **e);
void big_div(const bigint_t *a, const bigint_t *b, bigint_t **d);
void big_div_x(const bigint_t *a, const bigint_t *b, bigint_t **d);
void big_div_x_2(const bigint_t *a, const bigint_t *b, bigint_t **d);
bool big_bit_and_one(bigint_t *a);
void big_div_2(const bigint_t *a, const bigint_t *b, bigint_t **c);

// Assets
void big_assert(bigint_t **b1, bigint_t **b2);
void big_assert_str(char* str, bigint_t **b2);
void big_print(const bigint_t **a);
void big_alloc(bigint_t **b);
void big_alloc_2(bigint_t **b, int len);
void big_copy(const bigint_t *a, bigint_t **b);
void big_copy_ref(const bigint_t *a, bigint_t **b);
bool big_cmp(bigint_t *a, bigint_t *b);

// Multi
void big_init_m(int len, ...);
void big_end_m(int len, ...);
void big_set_m(int len, ...);

// Hex
int big_get_hex(int a, int base);
int big_check_set_base(const bigint_t *a, bigint_t **b);

#endif
