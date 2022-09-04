//                                                                            //
#ifndef LIGHTBIG_H
#define LIGHTBIG_H 1

#include <stdbool.h>
#include "lightdefs.h"

#define DEC 10
#define HEX 16
#define MAXSTR 512
#define BIGLEN 512
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
typedef const big cb;

// Init
void big_end(big **a);
void big_init(big **a);
void big_free(big **a);
void big_final(big **a);
void big_end_str(char *a);
void big_set_null(big **b);
void big_get(cb *a, char *b);
void big_clear_zeros(big **b);
void big_set(char *a, big **b);

// Operations
bool big_bit_and_one(big *a);
void big_add(cb *a, cb *b, big **c);
void big_mul(cb *a, cb *b, big **c);
void big_sub(cb *a, cb *b, big **c);
void big_mod(cb *a, cb *b, big **c);
void big_div(cb *a, cb *b, big **c);
void big_div_sub(cb *a, cb *b, big **c);

// Assets
void big_print(cb **a);
void big_alloc(big **b);
bool big_cmp(cb *a, cb *b);
void big_copy(cb *a, big **c);
void big_copy_ref(cb *a, big **b);
bool big_cmp_str(char *str, cb *a);
void big_assert(big **b1, big **b2);
void big_alloc_len(big **b, int len);
void big_assert_str(char *str, big **b2);
void big_resize(big **a, int old_len, int new_len);

// Multi
void big_end_m(int len, ...);
void big_set_m(int len, ...);
void big_init_m(int len, ...);
void big_free_m(int len, ...);
void big_final_m(int len, ...);
void big_alloc_m(int len, ...);
void big_alloc_max_m(int len, ...);

// Hex
i08 big_get_hex(i08 a, i08 base);
i08 big_check_set_base(cb *a, big **b);

#endif
