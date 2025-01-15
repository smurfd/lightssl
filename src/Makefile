CC:=gcc -O3 -Wall -pedantic -std=c99
BUILD:=.build

all: mkbuilddir lightciphers lighttools lightcrypto1 lighthash lightkeys lightaes test
local: mkbuilddir lightciphers lighttools lightcrypto1 lighthash lightkeys lightaes test_local

mkbuilddir:
	mkdir -p ${BUILD}

lightciphers:
	${CC} -c lightciphers.c -o ${BUILD}/lightciphers.o

lightcrypto1:
	${CC} -c lightcrypto.c -o ${BUILD}/lightcrypto.o

lighthash:
	${CC} -c lighthash.c -o ${BUILD}/lighthash.o

lightkeys:
	${CC} -c lightkeys.c -o ${BUILD}/lightkeys.o

lighttools:
	${CC} -c lighttools.c -o ${BUILD}/lighttools.o

lightaes:
	${CC} -c lightaes.c -o ${BUILD}/lightaes.o

test:
	make -Ctests

test_local:
	make -Ctests local
