CC := gcc -O3 -Wall -pedantic -std=c99
BUILD := .build

all: mkbuilddir hash ecc ecdsa test
local: mkbuilddir hash ecc ecdsa test_local

mkbuilddir:
	mkdir -p ${BUILD}

ecc:
	${CC} -c ecc.c -o .build/ecc.o

ecdsa:
	${CC} -c ecdsa.c -o .build/ecdsa.o

hash:
	${CC} -c ../../../hash.c -o .build/hash.o

test:
	make -Ctests

test_local:
	make -Ctests local
