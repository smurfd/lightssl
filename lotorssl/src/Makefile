CC:=gcc -O3 -Wall -pedantic -std=c99
BUILD:=.build

all: mkbuilddir cryp hash keys ciph test
local: mkbuilddir cryp hash keys ciph test_local

mkbuilddir:
	mkdir -p ${BUILD}

cryp:
	${CC} -c cryp.c -o ${BUILD}/cryp.o

hash:
	${CC} -c hash.c -o ${BUILD}/hash.o

keys:
	${CC} -c keys.c -o ${BUILD}/keys.o

ciph:
	${CC} -c ciph.c -o ${BUILD}/ciph.o

test:
	make -Ctests

test_local:
	make -Ctests local
