//                                                                            //
#ifndef LIGHTBIG_H
#define LIGHTBIG_H 1

#include "lightdefs.h"
#include <stdbool.h>

#define MAXSTR 512
#define BIGLEN 1024
#define DEC 10
#define HEX 16
#define LEN sizeof(i08)

typedef struct {
  i08 *dig;
  int len;
  i08 base;
  bool neg;
  bool null;
  bool alloc_t;
  bool alloc_d;
} bigint_t;

typedef bigint_t big;

// Init
void big_get(const big *a, char *b);
void big_init(big **a);
void big_end(big **a);
void big_end_str(char *a);
void big_set(char *a, big **b);
void big_set_null(big **b);
void big_clear_zeros(big **b);
void big_free(big **a);
void big_final(big **a);

// Operations
void big_add(const big *a, const big *b, big **c);
void big_mul(const big *a, const big *b, big **c);
void big_sub(const big *a, const big *b, big **c);
void big_mod(const big *a, const big *b, big **c);
void big_div(const big *a, const big *b, big **c);
void big_div_sub(const big *a, const big *b, big **c);
void big_div_internal(const big *a, const big *b, big **c);
void big_sub_internal(const big *a, const big *b, big **c);
bool big_bit_and_one(big *a);

// Assets
void big_assert(big **b1, big **b2);
void big_assert_str(char *str, big **b2);
void big_print(const big **a);
void big_alloc(big **b);
void big_alloc_len(big **b, int len);
void big_copy(const big *a, big **c);
void big_copy_ref(const big *a, big **b);
bool big_cmp(const big *a, const big *b);
bool big_cmp_str(char *str, const big *a);
void big_resize(big **a, int old_len, int new_len);

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
i08 big_check_set_base(const big *a, big **b);

#endif
