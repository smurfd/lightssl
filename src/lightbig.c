#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdbool.h>
#include "lightbig.h"

// TODO: obviously huge room for improvement
// TODO: handle hex not just base 10
// TODO: handle negative numbers
// TODO: multiplication
// TODO: division
// TODO: modulo
// TODO: unlimited(...) arguments per op?
// FIXME: If you DONT find bugs/leaks/securityissues let me know ;)

void big_init(bigint_t **b) {
  *b = (bigint_t*)malloc(BIGLEN);
  (*b)->d = (char*) malloc(BIGLEN);
  (*b)->length = 0;
  (*b)->neg = false;
}

void big_set(bigint_t **b, char* str) {
  memset((*b)->d, 0, strlen((*b)->d));
  memcpy((*b)->d, str, strlen(str));
}

void big_cls(bigint_t **b) {
  memset((*b)->d, 0, strlen((*b)->d));
}

void big_print(bigint_t **b) {
  printf("%s\n", (*b)->d);
}

void big_end(bigint_t **b) {
  free((*b)->d);
  free(*b);
}

void big_add(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int min, mix, max, carry, newd, m;
  char *ps1, *ps2;

  carry = 0;
  m = 0;

  min = strlen((*b1)->d);
  max = strlen((*b2)->d);
  ps1 = (*b2)->d;
  ps2 = (*b1)->d;

  if (((*b1)->d[0] == '9' || (*b2)->d[0] == '9') && (max == min)) {
    (*r)->d[0] = '1';
    m = 1;
  }

  if (min > max) {
    min = strlen((*b2)->d);
    max = strlen((*b1)->d);
    ps1 = (*b1)->d;
    ps2 = (*b2)->d;
  }
  mix = max - min;

  for (int i=0; i<mix; i++) {
    (*r)->d[i] = ps1[i];
  }

  for (int i=0; i<min; i++) {
    newd = (ps1[max-1-i]+ps2[min-1-i])-'0'+carry;
    if (carry == 1) {
      carry = 0;
    }
    if (newd > '9') {
      carry = 1;
      newd = newd - 10;
    }
    (*r)->d[max-1-i] = newd;
  }

  (*r)->d[max+m] = '\0';
}

void big_sub(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int min, mix, max, carry, newd, m;
  char *ps1, *ps2;

  carry = 0;
  m = 0;

  min = strlen((*b1)->d);
  max = strlen((*b2)->d);
  ps1 = (*b2)->d;
  ps2 = (*b1)->d;

  if (min >= max) {
    min = strlen((*b2)->d);
    max = strlen((*b1)->d);
    ps1 = (*b1)->d;
    ps2 = (*b2)->d;
  } else {
    (*r)->neg = true;
    (*r)->d[0] = '-';
    m = 1;
  }
  mix = max - min;

  for (int i=0; i<mix; i++) {
    (*r)->d[i+m] = ps1[i];
  }

  for (int i=0; i<min; i++) {
    newd = (ps1[max-i-1]-ps2[min-i-1])+'0'+carry;
    if (carry != 0) {
      carry = 0;
    }
    if (newd < '0') {
      carry = -1;
      newd = newd + 10;
    } else if (newd > '9') {
      carry = 1;
      newd = newd - 10;
    }
    (*r)->d[max-i-1+m] = newd;
  }
  (*r)->d[max+m] = '\0';
}

void big_mul(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int min, mix, max, carry, newd, m, len, d1, d2, x, y, count;
  char *ps1, *ps2;
  bigint_t *tmp, *tmpr, *rr;

  carry = 0;
  m = 0;
  big_init(&rr);
  big_init(&tmp);
  big_init(&tmpr);
  d1 = strlen((*b1)->d);
  d2 = strlen((*b2)->d);
  count = d1 + d2 - 1;
  if (((*b1)->neg == true && (*b2)->neg == true) || ((*b1)->neg == false && (*b2)->neg == false)) {
    (*r)->neg = false;
  } else {
    (*r)->neg = true;
    (*r)->d[0] = '-';
    m = 1;
  }
  for (int j=d2-1; j>=0; j--) {
    for (int i=d1-1; i>=0; i--) {
      char str1[2] = {(*b1)->d[i] , '\0'};
      char str2[5] = "";
      count = count - 1;
      x = (int)(*b1)->d[i]-'0';
      y = (int)(*b2)->d[j]-'0';
      (*rr).d[count] = (*rr).d[count] + carry + x*y;
      carry = 0;
      for(;;) {
        for (;;) {
          if ((*rr).d[count] < '0') {
            (*rr).d[count] = (*rr).d[count] + '0';
          } else {
            break;
          }
        }
        if ((*rr).d[count] > '9') {
          (*rr).d[count] = (*rr).d[count] - '9' -1;
          carry = carry + 1;
        } else {
          if ((*rr).d[count] < '0') {
            (*rr).d[count] = (*rr).d[count] + '0';
          }
          break;
        }

        if ((*rr).d[count] < '0') {
          (*rr).d[count] = (*rr).d[count] + '0';
        }
      }
    }
    count = count + (d1-1);
  }
  (*r)->d[d1+d2-1] = '\0';
  (*r) = *(&rr);
}

void big_div(bigint_t **b1, bigint_t **b2, bigint_t **r) {

}

void big_mod(bigint_t **b1, bigint_t **b2, bigint_t **r) {

}
