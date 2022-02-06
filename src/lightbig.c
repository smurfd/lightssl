//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdbool.h>
#include "lightbig.h"

// TODO: obviously huge room for improvement
// TODO: handle hex not just base 10
// TODO: free()
// TODO: add multifunctions to save lines like: a+b-c*d
// FIXME: If you DONT find bugs/leaks/securityissues let me know ;)

//
// Initialize a bigint
void big_init(bigint_t **a) {
  (*a) = calloc(sizeof(bigint_t), sizeof(bigint_t));
  (*a)->neg = false;
}

//
// Initialize several bigint
void big_init_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_init(va_arg(valist, bigint_t**));
  }
  va_end(valist);
}

//
// Clear a bigint
void big_end(bigint_t **a) {
  if ((*a)->dig != NULL) {
    free((*a)->dig);
  }
  if ((*a) != NULL) {
    free((*a));
  }
}

//
// Clear several bigint
void big_end_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_end(va_arg(valist, bigint_t**));
  }
  va_end(valist);
}

//
// Set several bigint
void big_set_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_set("", va_arg(valist, bigint_t**));
  }
  va_end(valist);
}

//
// Allocate memory for digits
void big_alloc(bigint_t **b) {
  (*b)->dig = calloc((*b)->len * sizeof(int), sizeof(int));
}

//
// Copy data
void big_copy(bigint_t *a, bigint_t **b) {
  for (int f = 0; f < (*a).len; f++) {
    (*b)->dig[f] = (*a).dig[f];
  }
}

// Copy data refs, replaces (*a) = (*b)
void big_copy_ref(bigint_t *a, bigint_t **b) {
  (*b)->neg = (*a).neg;
  (*b)->len = (*a).len;
  big_alloc(&(*b));
  for (int l=0; l<(*a).len; l++) {
    (*b)->dig[l] = (*a).dig[l];
  }
}

//
// Set a bigint from string
void big_set(char *a, bigint_t **b) {
  int skip;

  skip = 0;
  big_init(b);
  if (a[0] == '-') {
    (*b)->neg = true;
    skip++;
  }
  if (strcmp("0", a) == 0) {
    (*b)->len = 1;
    big_alloc(&(*b));
    (*b)->dig[0] = 0;
  } else if (strcmp("", a) == 0) {
    (*b)->len = 1;
    big_alloc(&(*b));
  } else {
    while (a[skip] == '0') {
      skip++;
    }

    (*b)->len = strlen(a) - skip;
    if ((*b)->len == 0) {
      (*b)->len++;
      big_alloc(&(*b));
      (*b)->dig[0] = 0;
    } else {
      big_alloc(&(*b));
      for (int i = 0; i < (*b)->len; i++) {
        (*b)->dig[i] = a[skip + i] - '0';
      }
    }
  }
}

//
// Clear initial zero
void big_clear_zero(bigint_t **b) {
  if ((*b)->dig[0] == 0) {
    (*b)->len--;
    (*b)->dig++;
  }
}

//
// Clear initial zero
void big_clear_zero2(bigint_t **b) {
  if ((*b)->dig[0] == 0 && (*b)->len != 1) {
    (*b)->len--;
    (*b)->dig++;
  }
}

//
// Clear initial zeros
void big_clear_zeros(bigint_t **b) {
  while ((*b)->dig[0] == 0 && (*b)->len >= 0) {
    (*b)->len--;
    (*b)->dig++;
  }
  // if the string only contains zeros atleast save one
  if (strcmp("", big_get(*b)) == 0) {
    big_set("0", b);
  }
}

//
// Get string from bigint
char *big_get(bigint_t *a) {
  char *b = malloc(BIGLEN);
  int mod = 0;

  // -3 is digit for '-'?
  if (a->neg == true && a->dig[0] != -3) {
    mod = 1;
    b[0] = '-';
  }
  for (int i = 0; i < a->len; i++) {
    b[i+mod] = a->dig[i] + '0';
  }
  return b;
}

//
// Bigint addition
void big_add(bigint_t *a, bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry;
  carry = 0;
  big_init(c);
  if ((*a).neg && (*b).neg) {
    char *a1 = malloc(BIGLEN);
    char *b1 = malloc(BIGLEN);
    bigint_t *aa, *bb;
    sprintf(a1, "%s", big_get(a));
    sprintf(b1, "%s", big_get(b));
    big_init_m(2, &aa, &bb);
    big_set(a1, &aa);
    big_set(b1, &bb);
    (*aa).neg = false;
    (*bb).neg = false;
    big_add(aa, bb, c);
  } else {
    if (a == NULL) {
      c = NULL;
    } else if (b == NULL) {
      c = NULL;
    } else if (strcmp(big_get(a), "0") == 0) {
      big_copy_ref(b, c);
    } else if (strcmp(big_get(b), "0") == 0) {
      big_copy_ref(a, c);
    } else {
      (*c)->len = (a->len > b->len ? a->len : b->len) + 1;
      big_alloc(&(*c));
      i = a->len - 1;
      j = b->len - 1;
      k = (*c)->len - 1;

      while (i >= 0 || j >= 0 || carry > 0) {
        if (i >= 0 && j >= 0) {
          tmp = a->dig[i] + b->dig[j];
        } else if (i >= 0) {
          tmp = a->dig[i];
        } else if (j >= 0) {
          tmp = b->dig[j];
        } else {
          tmp = 0;
        }
        tmp += carry;
        carry = tmp / 10;
        (*c)->dig[k] = tmp % 10;
        i--;
        j--;
        k--;
      }
      big_clear_zero(&(*c));
    }
  }
}

//
// Bigint multiplication
void big_mul(bigint_t *a, bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, push_left;

  big_init(c);
  if (a == NULL) {
    c = NULL;
  } else if (b==NULL) {
    c = NULL;
  } else if ((*a).len == 1 && (*a).dig[0] == 0) {
    (*c)->len = 1;
    big_alloc(&(*c));
    big_set("0", c);
  } else if ((*b).len == 1 && (*b).dig[0] == 0) {
    (*c)->len = 1;
    big_alloc(&(*c));
    big_set("0", c);
  } else {
    (*c)->len = a->len + b->len;
    big_alloc(&(*c));
    i = a->len - 1;
    j = b->len - 1;
    k = (*c)->len - 1;
    carry = 0;
    push_left = 0;
    while (i >= 0) {
      k = (*c)->len - 1 - push_left++;
      j = b->len - 1;
      while (j >= 0 || carry > 0) {
        if (j >= 0) {
          tmp = a->dig[i] * b->dig[j];
        } else {
          tmp = 0;
        }
        tmp += carry;
        carry = tmp / 10;
        (*c)->dig[k] += tmp % 10;
        carry += (*c)->dig[k] / 10;
        (*c)->dig[k] = (*c)->dig[k] % 10;
        j--;
        k--;
      }
      i--;
    }
    big_clear_zeros(&(*c));
  }
}

//
// Bigint subtraction
void big_sub(bigint_t *a, bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry;
  bigint_t *d, *e;

  big_init_m(3, c, &d, &e);
  if ((*a).neg && (*b).neg) {
    char *a1 = malloc(BIGLEN);
    char *b1 = malloc(BIGLEN);
    bigint_t *aa, *bb;
    sprintf(a1, "%s", big_get(a));
    sprintf(b1, "%s", big_get(b));
    big_init_m(2, &aa, &bb);
    big_set(a1, &aa);
    big_set(b1, &bb);
    (*aa).neg = false;
    (*bb).neg = false;
    big_sub(aa, bb, c);
  } else if ((*a).neg || (*b).neg) {
    big_add(a, b, c);
  } else {
    if (a == NULL) {
      c = NULL;
    } else if (b == NULL) {
      c = NULL;
    } else if (strcmp(big_get(a), "0") == 0) {
      big_copy_ref(b, c);
      big_clear_zero2(&(*c));
    } else if (strcmp(big_get(b), "0") == 0) {
      big_copy_ref(a, c);
      big_clear_zero2(&(*c));
    } else {
      (*c)->len = (a->len > b->len ? a->len : b->len);
      big_alloc(&(*c));

      if (a->len > b->len) {
        (*d).len = a->len;
        big_alloc(&d);
        (*e).len = b->len;
        big_alloc(&e);
        big_copy(a, &d);
        big_copy(b, &e);
        i = d->len - 1;
        j = e->len - 1;
      } else if (b->len > a->len) {
        (*d).len = b->len;
        big_alloc(&d);
        (*e).len = a->len;
        big_alloc(&e);
        (*c)->neg = true;
        big_copy(b, &d);
        big_copy(a, &e);
        i = d->len - 1;
        j = e->len - 1;
      } else {
        (*d).len = a->len;
        big_alloc(&d);
        (*e).len = b->len;
        big_alloc(&e);
        big_copy(a, &d);
        big_copy(b, &e);
        i = d->len - 1;
        j = e->len - 1;
      }

      carry = 0;
      k = (*c)->len - 1;
      while (i >= 0 || j >= 0 || carry > 0) {
        if (i >= 0 && j >= 0) {
          tmp = (*d).dig[i]-(*e).dig[j];
          if (tmp < 0) {
            if (i == 0 && j == 0) {
              (*c)->neg = true;
            }
            tmp += 10;
            d->dig[i-1] -= 1;
          }
        } else if (i >= 0) {
          tmp = d->dig[i];
        } else if (j >= 0) {
          tmp = e->dig[j];
        } else {
          tmp = 0;
        }
        tmp -= carry;
        carry = tmp / 10;
        (*c)->dig[k] = tmp % 10;
        i--;
        j--;
        k--;
      }
      big_clear_zero2(&(*c));
      if (j > i) {
        (*c)->neg = true;
      }
    }
  }
}

//
// Bigint division
void big_div_x(bigint_t *a, bigint_t *b, bigint_t **d) {
  char *str;
  uint64_t co;
  bigint_t *c, *e, *f;

  co = 0;
  big_init_m(4, d, &c, &e, &f);
  (*d)->len = (a->len > b->len ? a->len : b->len);
  big_alloc(d);
  big_set_m(2, &e, &f);
  big_set(big_get(a), &c);
  big_set(big_get(a), &f);
  c->neg = false;
  while (c->len >= b->len && c->neg == false) {
    big_set_m(1, &e);
    big_sub(c, b, &e);
    big_copy_ref(e, &c);
    big_clear_zero(&c);
    co++;
  }
  if (c->neg == true) {
     co--;
  }
  str = (char*) malloc(sizeof(uint64_t));
  sprintf(str, "%llu", co);
  big_set(str, d);
  if (str) {
    free(str);
  }
}

void big_div(bigint_t *a, bigint_t *b, bigint_t **d) {
  int len, len123;
  bigint_t *c, *e, *w, *res;

  if (a == NULL) {
    d = NULL;
  } else if (b == NULL) {
    d = NULL;
  } else if (strcmp(big_get(a), big_get(b)) == 0) {
    big_set("1", d);
  } else if (strcmp(big_get(a), big_get(b)) <= 0 && strlen(big_get(a)) == strlen(big_get(b))) {
    big_set("0", d);
  } else if (strcmp(big_get(b), "1") == 0) {
    big_copy_ref(a, d);
  } else {
    len123 = 0;
    len = strlen(big_get(a)) - strlen(big_get(b));
    big_init_m(4, &c, &e, &w, &res);
    big_set_m(4, &c, &e, &w, &res);
    big_copy_ref(a, &c);
    big_copy_ref(b, &e);
    big_copy_ref(c, &w);

    for (int i = 0; i < len; i++) {
      big_copy_ref(b, &e);
      int len1 = strlen(big_get(c));
      int len2 = strlen(big_get(e));
      int len3 = len1-len2-1;
      if (len3 > 0) {
        int clen;
        char *ccc = malloc(BIGLEN);
        char *cc = malloc(BIGLEN);

        strcpy(cc, big_get(e));
        if (len1 >= len3 + 4) {
          len3 = len1 - 4;
        }
        // fill out with zeros, hack to save tons of iterations
        for (int j = 0; j <= len3; j++) {
          cc[len2+j] = '0';
        }
        cc[len3+1] = '\0';
        big_set(cc, &e);
        bigint_t *v, *x, *y, *z, *f;
        big_init_m(5, &v, &x, &y, &z, &f);
        big_set_m(5, &v, &x, &y, &z, &f);
        big_copy_ref(c, &w);
        big_copy_ref(e, &x);
        big_div_x(w, x, &y);
        strcpy(ccc, big_get(y));
        clen = strlen(ccc);
        for (int k = 0; k < clen; k++) {
          if (i == 0 && clen > 1) {
            // 1st run, populate result with big-num divs ie first nums in result
            for (uint64_t l = 0; l < strlen(ccc); l++) {
              (*res).dig[l] = ccc[l] - '0';
            }
            (*res).len = strlen(ccc);
            len123 = strlen(ccc);
            break;
          } else if (clen > 1) {
            // If the number of divisions exceed 9 we do this
            bigint_t *tmp = NULL, *tmp2 = NULL;
            big_init_m(2, &tmp, &tmp2);
            char *ccc1 = malloc(BIGLEN);

            // FIXME: merge with below if?
            if ((*res).len < clen) {
              (*res).len = clen;
            }
            strcpy(ccc1, big_get(res));
            // This hack adds a 0 to thec 1st couple of numbers so they add upp correctly
            if (clen > 3 && i > 1) {
              ccc1[clen] = '0';
              ccc1[clen+1] = '\0';
            }
            big_set(ccc1, &tmp);
            big_set(ccc, &tmp2);
            // FIXME: merge this with above if?
            (*res).len = strlen(ccc) > strlen(ccc1) ? strlen(ccc):strlen(ccc1);
            len123  = strlen(ccc) > strlen(ccc1) ? strlen(ccc):strlen(ccc1);
            big_add(tmp2, tmp, &res);
            // FIXME: Why this hack?
            if ((*res).dig[len123] == 0) {
              len123--;
              (*res).len = len123 + 1;
            }
            break;
          } else {
            // Modify the where to position the next character depening on the above hacks
            // to save repetitions
            if (i==1 && clen == 1 && len123 > 4) {
              len123--;
            }
            if (i==1 && clen == 1 && len123 == 3) {
              len123--;
            }
            if (len123 > (*res).len && i > 4) {
              (*res).len = len123+1;
            }
            (*res).dig[len123] = ccc[k] - '0';
          }
        }
        (*res).len = len123;
        big_mul(x, y, &z);
        big_set(big_get(w), &f);
        big_sub(w, z, &v);
        big_copy_ref(v, &c);
        big_copy_ref(f, &w);
        len123++;
      } else {
        bigint_t *ff;
        big_init_m(1, &ff);
        big_set_m(1, &ff);
        big_clear_zeros(&c);
        big_set(big_get(c), &ff);
        big_div_x(c, b, d);
        if (strcmp(big_get(*d), "0") != 0) {
          int mod = 1;
          if (i > 4) {
            mod = 2;
          }
          (*res).len = i + mod;
          for (uint64_t j = 0; j < strlen(big_get(*d)); j++) {
            (*res).dig[i+j+(mod-1)] = (*d)->dig[j];
            (*res).len = i + j + mod;
          }
        }
        big_end_m(1, &ff);
        break;
      }
    }
    big_clear_zeros(&res);
    big_copy_ref(res, d);
  }
}

//
// Bigint modulo
void big_mod(bigint_t *a, bigint_t *b, bigint_t **e) {
  bigint_t *c, *d, *f;

  if (a == NULL) {
    e = NULL;
  } else if (b == NULL) {
    e = NULL;
  } else {
    big_init_m(4, &c, &d, &f, e);
    big_set_m(1, &c, &d);
    big_set_m(1, &f);
    big_copy_ref(a, &f);
    big_div(a, b, &c);
    big_mul(c, b, &d);
    (*e)->len = (f->len > d->len ? f->len : d->len);
    big_alloc(e);
    big_sub(f, d, e);
    big_clear_zeros(&(*e));
  }
}

//
// Print a bigint
void big_print(bigint_t **a) {
  char *c = (char*) malloc((*a)->len);

  printf("%s\n", big_get(*a));
  free(c);
}

// Assert
void big_assert(bigint_t **b1, bigint_t **b2) {
  assert(strcmp(big_get(*b1), big_get(*b2)) == 0);
}

