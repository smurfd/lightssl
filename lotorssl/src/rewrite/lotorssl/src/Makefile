CC := gcc -O3 -Wall -pedantic -std=c99
BUILD := .build

all: mkbuilddir hash ecc test
local: mkbuilddir hash ecc test_local

mkbuilddir:
	mkdir -p ${BUILD}

ecc:
	${CC} -c ecc.c -o .build/ecc.o

hash:
	${CC} -c ../../../hash.c -o .build/hash.o

test:
	make -Ctests

test_local:
	make -Ctests local
