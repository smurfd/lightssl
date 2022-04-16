//                                                                            //
#ifndef LIGHTBIG_H
#define LIGHTBIG_H 1

#include "lightdefs.h"
#include <stdbool.h>

#define MAXSTR 512
#define BIGLEN 1024
#define DEC    10
#define HEX    16
#define LEN    sizeof(i08)

typedef struct {
  i08 *dig;
  int len;
  i08 base;
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
void big_free(bigint_t **a);
void big_final(bigint_t **a);

// Operations
void big_add(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_mul(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_sub(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_mod(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_div(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_div_sub(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_div_internal(const bigint_t *a, const bigint_t *b, bigint_t **c);
void big_sub_internal(const bigint_t *a, const bigint_t *b, bigint_t **c);
bool big_bit_and_one(bigint_t *a);

// Assets
void big_assert(bigint_t **b1, bigint_t **b2);
void big_assert_str(char *str, bigint_t **b2);
void big_print(const bigint_t **a);
void big_alloc(bigint_t **b);
void big_alloc_len(bigint_t **b, int len);
void big_copy(const bigint_t *a, bigint_t **c);
void big_copy_ref(const bigint_t *a, bigint_t **b);
bool big_cmp(const bigint_t *a, const bigint_t *b);
bool big_cmp_str(char *str, const bigint_t *a);
void big_resize(bigint_t **a, int old_len, int new_len);

// Multi
void big_init_m(int len, ...);
void big_end_m(int len, ...);
void big_set_m(int len, ...);
void big_alloc_m(int len, ...);
void big_alloc_max_m(int len, ...);
void big_free_m(int len, ...);
void big_final_m(int len, ...);

// Hex
i08 big_get_hex(i08 a, i08 base);
i08 big_check_set_base(const bigint_t *a, bigint_t **b);

#endif
