#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lightdefs.h"

void lightecdh_bit_copy(bit *x, const bit y, cur* cc);
void lightecdh_point_copy(pt *p1, const pt p2, cur* cc);
void print_bit(bit a, cur* cc);
void lightecdh_curves_init(cur* cc);
void lightecdh_curves_end(cur* cc);

#endif
