CC := gcc -O3 -Wall -pedantic -std=c99
BUILD := ../.build

all: build runner
local: build runner_local

build:
	${CC} -o ${BUILD}/tests tests.c ${BUILD}/ecc.o ${BUILD}/hash.o -lpthread -lm

runner:
	${BUILD}/tests

runner_local:
	${BUILD}/tests local
