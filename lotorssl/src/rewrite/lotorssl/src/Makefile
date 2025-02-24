CC := gcc -Ofast -Wall -pedantic -std=c99
BUILD := .build

all: mkbuilddir hash ecdsa test
local: mkbuilddir hash ecdsa test_local

mkbuilddir:
	mkdir -p ${BUILD}

ecdsa:
	${CC} -c ecdsa.c -o .build/ecdsa.o

hash:
	${CC} -c ../../../hash.c -o .build/hash.o

test:
	make -Ctests

test_local:
	make -Ctests local
