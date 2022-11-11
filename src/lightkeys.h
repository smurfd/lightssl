#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lightdefs.h"

void lightkeys_bit_copy(bit *x, const bit y, cur* cc);
void lightkeys_point_copy(pt *p1, const pt p2, cur* cc);
void lightkeys_print_bit(bit a, cur* cc);
void lightkeys_curves_init(cur* cc);
void lightkeys_curves_end(cur* cc);

#endif
