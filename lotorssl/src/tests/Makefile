CC:=gcc -Ofast -Wall -pedantic -std=c99
BUILD:=../.build

all: mkcrt tests runner
local: mkcrt tests runner_local

mkcrt:
	echo "66612345678966601234567890666" | openssl cms -EncryptedData_encrypt -aes128 -secretkey 31337DEADBEEF666999ABCDEF31337FF -outform der > ${BUILD}/ca128.cms
	echo "66612345678966601234567890666" | openssl cms -EncryptedData_encrypt -aes256 -secretkey 31337DEADBEEF666999ABCDEF31337FF31337DEADBEEF666999ABCDEF31337FF -outform der > ${BUILD}/ca256.cms
	openssl ecparam -name secp384r1 -genkey -noout -out ${BUILD}/ca.key

tests:
	${CC} -o ${BUILD}/tests tests.c ${BUILD}/ciph.o ${BUILD}/keys.o ${BUILD}/hash.o ${BUILD}/cryp.o -lpthread -lm

runner:
	${BUILD}/tests

runner_local:
	${BUILD}/tests local
