CL:=gcc -O3 -Wall -pedantic -std=c99
CC:=gcc -O3 -Wall -pedantic -std=c99
BUILD:=.build

all: mkbuilddir lightciphers lighttools lightcrypto1 lighthash lightkeys test

mkbuilddir:
	mkdir -p ${BUILD}

lightciphers:
	${CL} -c lightciphers.c -o ${BUILD}/lightciphers.o

lightcrypto1:
	${CL} -c lightcrypto.c -o ${BUILD}/lightcrypto.o

lighthash:
	${CL} -c lighthash.c -o ${BUILD}/lighthash.o

lightkeys:
	${CL} -c lightkeys.c -o ${BUILD}/lightkeys.o

lighttools:
	${CL} -c lighttools.c -o ${BUILD}/lighttools.o

test:
	make -Ctests
