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
void big_get(const bigint_t *a, char *b);
void big_init(bigint_t **a);
void big_end(bigint_t **a);
void big_end_str(char *a);
void big_set(char *a, bigint_t **b);
void big_clear_zeros(bigint_t **b);

// Operations
void big_add(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_mul(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_sub(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_mod(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_div(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_div_sub(const bigint_t *a, const bigint_t *b, bigint_t **c);
bool big_bit_and_one(bigint_t *a);

// Assets
void big_assert(bigint_t **b1, bigint_t **b2);
void big_assert_str(char* str, bigint_t **b2);
void big_print(const bigint_t **a);
void big_alloc(bigint_t **b);
void big_alloc_len(bigint_t **b, int len);
void big_copy(const bigint_t *a, bigint_t **b);
void big_copy_ref(const bigint_t *a, bigint_t **b);
bool big_cmp(bigint_t *a, bigint_t *b);
bool big_cmp_str(char *str, bigint_t *a);

// Multi
void big_init_m(int len, ...);
void big_end_m(int len, ...);
void big_set_m(int len, ...);
void big_alloc_max_m(int len, ...);

// Hex
int big_get_hex(int a, int base);
int big_check_set_base(const bigint_t *a, bigint_t **b);

#endif
