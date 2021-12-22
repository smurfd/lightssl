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

void big_set_size(bigint_t **b, char* str, uint64_t size) {
  memset((*b)->d, 0, size);
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
    if (carry != 0) { // reset the carry
      carry = 0;
    }
    if (newd < '0') {
      carry = -1;
      newd = newd + 10;
      if (max-i-3+m >= 0) {
        if (ps1[max-i-3+m] >= '1' && ps1[max-i-3+m] <= '9') {
          (*r)->d[max-i-3+m] = (ps1[max-i-3])+carry;
        } else if (ps1[max-i-3+m] == '0') {
        }
      } else {
        carry = -1;
        (*r)->d[max-i-3+m] = (ps1[max-3-i])+carry;
      }
    } else if (newd > '9') {
      carry = 1;
      newd = newd - 10;
    } else if (max-i-3+m >= 0) {
      if (ps1[max-i-3+m] == '0') {
        if (ps1[max-i-2+m] == '0') {
          (*r)->neg = true;
        }
      }
    }
    (*r)->d[max-i-1+m] = newd;
  }
  (*r)->d[max+m] = '\0';
}

void big_mul(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int carry, m, d1, d2, count, c1, c2, c3, cc, cmax, dig, newdig, newdig2;
  bigint_t *rr;

  big_init(&rr);
  big_cls(&rr);
  carry = 0;
  m = 0;
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

  c1 = d1-1;
  c2 = d2-1;
  cmax = (d1-1)+(d2-1);
  c3 = cmax;
  cc = 0;
  dig = 0;
  newdig = 0;
  newdig2 = 0;
  carry = 0;

  for (;;) {
    // Control loop
    if (c2 < 0) {
      cc = cc + 1;
      c3 = cmax - cc;
      c2 = d2 - 1;
      c1 = c1 - 1;
      if (c1 < 0) {
        break;
      }
    }

    newdig = ((*b2)->d[c2]-'0')*((*b1)->d[c1]-'0') + '0';
    // Check if character * character exceeds 1 character as result
    if (newdig >= '0' && newdig <= '9') {
      dig = newdig;
    } else if (newdig > '9') {
      dig = newdig-('0'*(int)(newdig / '0'));
      if (dig > 9) {
        (*rr).d[c3-1] = (*rr).d[c3-1] + (dig / 10);
        carry = (int)(dig / 10);
        dig = dig - (carry*10);
        carry = 0;
      }
      dig = dig + '0';
      if (c2 == 0) {
        dig = dig + carry;
        carry = 0;
      }
    }

    newdig2 = (*rr).d[c3] + dig;
    carry = 0;
    // Check if character + possible other character + carry exceeds 1 character
    if (newdig2 >= '0' && newdig2 <= '9') {
      dig = newdig2;
    } else if (newdig2 > '9') {
      dig = newdig2-('0'*(newdig2/'0'));
      if (dig > 9) {
        if (c1 == 0 && c2 == 0) {
          char *tmpr;
          tmpr = (char*) malloc(sizeof((*rr).d+32));
          tmpr[0]='1';
          if ((*rr).d[0]>='0' && (*rr).d[0] <='9') {
            tmpr[1]=(*rr).d[0];
          } else {
            tmpr[1]='0';
          }
          for (int i=0; i<(int)strlen((*rr).d); i++) {
            tmpr[i+2] = (*rr).d[i];
          }
          tmpr[strlen((*rr).d)+2]='\0';
          big_set_size(&rr, tmpr, sizeof(tmpr));
          free(tmpr);
          c3 = c3 + 1;
        } else {
          (*rr).d[c3-1] = (*rr).d[c3-1] + (dig / 10);
        }
        carry = (int)(dig / 10);
        dig = dig - (carry*10);
        carry = 0;
      }
      dig = dig + '0';
      if (c2 == 0) {
        dig = dig + carry;
        carry = 0;
      }
    }
    (*rr).d[c3] = dig;
    c2 = c2 - 1;
    c3 = c3 - 1;
  }

  (*r) = *(&rr);
  big_print(r);
}

int big_cmp(bigint_t **b1, bigint_t **b2) {
  // TODO: wayyyy better finegrained comparison
  int l1, l2, i, j, k; // -1=smaller, 0=alike, 1=bigger
  l1 = strlen((*b1)->d);
  l2 = strlen((*b2)->d);
  if (l1 > l2) {
    return -1;
  } else if(l1 < l2) {
    return 1;
  }
  for (i=0; i<l1-1; i++) {
    j = (*b1)->d[i];
    k = (*b2)->d[i];
    if (j<k) {
      return -1;
    }
  }
  return 0;
}

void big_div_u(bigint_t **b1, bigint_t **b2, uint64_t *co) {
  int xxx = 1;
  bigint_t *rr1, *rr2;
  big_init(&rr1);
  big_init(&rr2);
  (*rr1) = *(*b1);

  while ((*rr2).neg == false || xxx >= 0) {
    xxx = big_cmp(&rr1, b2);
    big_sub(&rr1, b2, &rr2);
    *co = *co+1;
    (*rr1) = (*rr2);
  }
  *co = *co-1;
}

void big_div(bigint_t **b1, bigint_t **b2, uint64_t *co) {
  if (strcmp((*b2)->d, "0") == 0) {
    printf("division by zero, no good!\n");
  }
  // Check if (*b2)->d < 0
  // Check if (*b1)->d < 0

  // should be positive values before this
  big_div_u(b1, b2, co);
}
