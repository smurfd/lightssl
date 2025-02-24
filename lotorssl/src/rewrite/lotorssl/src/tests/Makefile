CC := gcc -Ofast -Wall -pedantic -std=c99
BUILD := ../.build

all: build runner
local: build runner_local

build:
	${CC} -o ${BUILD}/tests tests.c ${BUILD}/ecdsa.o ${BUILD}/hash.o -lpthread -lm

runner:
	${BUILD}/tests

runner_local:
	${BUILD}/tests local
