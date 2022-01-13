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
// FIXME: If you DONT find bugs/leaks/securityissues let me know ;)

//
// Initialize a bigint
void big_init(bigint_t **a) {
  (*a) = malloc(sizeof(bigint_t));
  (*a)->neg = false;
}

//
// Initialize several bigint
void big_init_m(int len, ...) {
  va_list valist;
  va_start(valist, len);
  for (int i=0; i<len; i++) {
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
  for (int i=0; i<len; i++) {
    big_end(va_arg(valist, bigint_t**));
  }
  va_end(valist);
}

//
// Set several bigint
void big_set_m(int len, ...) {
  va_list valist;
  va_start(valist, len);
  for (int i=0; i<len; i++) {
    big_set("", va_arg(valist, bigint_t**));
  }
  va_end(valist);
}

//
// Set a bigint from string
void big_set(char *a, bigint_t **b) {
  big_init(b);

  int skip = 0;
  while(a[skip] == '0') {
    skip++;
  }

  (*b)->len = strlen(a) - skip;

  if((*b)->len == 0) {
    (*b)->len++;
    (*b)->dig = malloc((*b)->len * sizeof(int));
    (*b)->dig[0] = 0;
  } else {
    (*b)->dig = malloc((*b)->len * sizeof(int));
    for(int i = 0; i < (*b)->len; i++) {
      (*b)->dig[i] = a[skip + i] - '0';
    }
  }
}

//
// Get string from bigint
char *big_get(bigint_t *a) {
  char *b = malloc(a->len * sizeof(char));
  for(int i = 0; i < a->len; i++) {
    b[i] = a->dig[i] + '0';
  }
  return b;
}

//
// Bigint addition
void big_add(bigint_t *a, bigint_t *b, bigint_t **c) {
  big_init(c);
  (*c)->len = (a->len > b->len ? a->len : b->len) + 1;
  (*c)->dig = malloc((*c)->len * sizeof(int));
  int i = a->len - 1;
  int j = b->len - 1;
  int k = (*c)->len - 1;
  int carry = 0, tmp;

  while(i >= 0 || j >= 0 || carry > 0) {
    if(i >= 0 && j >= 0) {
      tmp = a->dig[i] + b->dig[j];
    } else if(i >= 0) {
      tmp = a->dig[i];
    } else if(j >= 0) {
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

  if((*c)->dig[0] == 0) {
    (*c)->len--;
    (*c)->dig++;
  }
}

//
// Bigint multiplication
void big_mul(bigint_t *a, bigint_t *b, bigint_t **c) {
  big_init(c);
  (*c)->len = a->len + b->len;
  (*c)->dig = malloc((*c)->len * sizeof(int));
  for(int i = 0; i < (*c)->len; i++) {
    (*c)->dig[i] = 0;
  }

  int i = a->len - 1;
  int j = b->len - 1;
  int k = (*c)->len - 1;
  int carry = 0, tmp, push_left = 0;
  while(i >= 0) {
    k = (*c)->len - 1 - push_left++;
    j = b->len - 1;
    while(j >= 0 || carry > 0) {
      if(j >= 0) {
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

  while((*c)->dig[0] == 0 && (*c)->len >= 0) {
    (*c)->len--;
    (*c)->dig++;
  }
}

//
// Bigint subtraction
void big_sub(bigint_t *a, bigint_t *b, bigint_t **c) {
  big_init(c);
  (*c)->len = (a->len > b->len ? a->len : b->len);
  (*c)->dig = malloc((*c)->len * sizeof(int));
  int i = a->len-1;
  int j = b->len-1;
  int k = (*c)->len-1;
  int carry = 0, tmp;
  while(i >= 0 || j >= 0 || carry > 0) {
    if(i >= 0 && j >= 0) {
      tmp = a->dig[i] - b->dig[j];
      if (tmp<0) {
        if (i==0 && j==0) {
          (*c)->neg = true;
        }
        tmp += 10;
        a->dig[i-1] -= 1;
      }
    } else if(i >= 0) {
      tmp = a->dig[i];
    } else if(j >= 0) {
      tmp = b->dig[j];
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

  if((*c)->dig[0] == 0) {
    (*c)->len--;
    (*c)->dig++;
  }
  if (j > i) {
    (*c)->neg = true;
  }
}

//
// Bigint division
void big_div_x(bigint_t *a, bigint_t *b, bigint_t **d) {
  bigint_t *c, *e, *f;
  big_init(&c);
  big_init(&e);
  big_init(&f);
  big_init(d);
  char *str;
  uint64_t co = 0;

  c->len = (a->len > b->len ? a->len : b->len);
  c->dig = malloc(c->len * sizeof(int));

  big_set_m(2, &e, &f);
  big_set(big_get(a), &c);
  big_set(big_get(a), &f);
  c->neg = false;
  while (c->len >= b->len && c->neg == false) {
    big_set_m(1, &e);
    big_sub(c, b, &e);
    (*c) = (*e);
    if(c->dig[0] == 0) {
      c->len--;
      c->dig++;
    }
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
  int len = strlen(big_get(a))-strlen(big_get(b));
  bigint_t *c, *e, *w, *res;
  big_init_m(4, &c, &e, &w, &res);
  big_set_m(4, &c, &e, &w, &res);
  (*c) = (*a);
  (*e) = (*b);
  (*w) = (*c);
  for (int i=0; i<len; i++) {
    (*e) = (*b);
    int len1 = strlen(big_get(c));
    int len2 = strlen(big_get(e));
    int len3 = len1-len2-1;
    if (len3 > 0) {
      char *cc = malloc(2568);
      strcpy(cc, big_get(e));
      if (len1 >= len3 + 4) {
        len3 = len1-4;
      }
      for (int j=0; j<=len3; j++) {
        cc[len2+j] = '0';
      }
      cc[len3+1] = '\0';
      big_set(cc, &e);
      bigint_t *v, *x, *y, *z, *f;
      big_init_m(5, &v, &x, &y, &z, &f);
      big_set_m(5, &v, &x, &y, &z, &f);
      (*w) = (*c);
      (*x) = (*e);
      big_div_x(w, x, &y);
      char *ccc = malloc(12048);
      strcpy(ccc, big_get(y));
      (*res).dig[i] = ccc[0]-'0';
      (*res).len = i+1;
      big_mul(x, y, &z);
      big_set(big_get(w), &f);
      big_sub(w, z, &v);
      (*c) = (*v);
      free(ccc);
      free(cc);
    } else {
      bigint_t *ff;
      big_init_m(1, &ff);
      big_set_m(1, &ff);
      big_set(big_get(c), &ff);
      big_div_x(ff, b, d);
      (*res).len = i+1;
      for (uint64_t j=0; j<strlen(big_get(*d)); j++) {
        (*res).dig[i+j] = (*d)->dig[j];
        (*res).len = i+1+j;
      }
      big_end_m(1, &ff);
      break;
    }
  }
  (*d) = &(*res);
}

//
// Bigint modulo
void big_mod(bigint_t *a, bigint_t *b, bigint_t **e) {
  bigint_t *c, *d;
  big_init_m(3, &c, &d, e);

  c->len = (a->len > b->len ? a->len : b->len);
  c->dig = malloc(c->len * sizeof(int));
  d->len = (a->len > b->len ? a->len : b->len);
  d->dig = malloc(d->len * sizeof(int));
  (*e)->len = (a->len > b->len ? a->len : b->len);
  (*e)->dig = malloc((*e)->len * sizeof(int));

  big_div(a, b, &c);
  big_mul(b, c, &d);
  big_sub(a, d, e);

  if (c->dig) {
    free(c->dig);
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

