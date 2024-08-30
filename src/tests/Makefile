CL:=gcc -O3 -Wall -pedantic -std=c99
CC:=gcc -O3 -Wall -pedantic -std=c99
BUILD:=../.build

all: mkcrt test_lightciphers_cbc test_lightciphers_cfb test_lightcrypto test_lighthash3 test_lighthash3_big test_lighthash3_shake test_lighthash3_shake_big\
	test_lighthash3_shake_ref test_lighthkeys_make test_lighthkeys_secr test_lighthkeys_sign test_lighthkeys_vrfy test_lighthkeys_write test_lightaes run

mkcrt:
	echo "66612345678966601234567890666" | openssl cms -EncryptedData_encrypt -aes128 -secretkey 31337DEADBEEF666999ABCDEF31337FF -outform der > ${BUILD}/ca128.cms
	echo "66612345678966601234567890666" | openssl cms -EncryptedData_encrypt -aes256 -secretkey 31337DEADBEEF666999ABCDEF31337FF31337DEADBEEF666999ABCDEF31337FF -outform der > ${BUILD}/ca256.cms
	openssl ecparam -name secp384r1 -genkey -noout -out ${BUILD}/ca.key

test_lightciphers_cbc:
	${CL} -o ${BUILD}/test_lightciphers_cbc test_lightciphers_cbc.c ${BUILD}/lightciphers.o -lpthread -lm

test_lightciphers_cfb:
	${CL} -o ${BUILD}/test_lightciphers_cfb test_lightciphers_cfb.c ${BUILD}/lightciphers.o -lpthread -lm

test_lightcrypto:
	${CL} -o ${BUILD}/test_lightcrypto test_lightcrypto.c ${BUILD}/lightcrypto.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthash3:
	${CL} -o ${BUILD}/test_lighthash3 test_lighthash3.c ${BUILD}/lighthash.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthash3_big:
	${CL} -o ${BUILD}/test_lighthash3_big test_lighthash3_big.c ${BUILD}/lighthash.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthash3_shake:
	${CL} -o ${BUILD}/test_lighthash3_shake test_lighthash3_shake.c ${BUILD}/lighthash.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthash3_shake_big:
	${CL} -o ${BUILD}/test_lighthash3_shake_big test_lighthash3_shake_big.c ${BUILD}/lighthash.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthash3_shake_ref:
	${CL} -o ${BUILD}/test_lighthash3_shake_ref test_lighthash3_shake_ref.c ${BUILD}/lighthash.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthkeys_make:
	${CL} -o ${BUILD}/test_lightkeys_make test_lightkeys_make.c ${BUILD}/lightkeys.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthkeys_secr:
	${CL} -o ${BUILD}/test_lightkeys_secr test_lightkeys_secr.c ${BUILD}/lightkeys.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthkeys_sign:
	${CL} -o ${BUILD}/test_lightkeys_sign test_lightkeys_sign.c ${BUILD}/lightkeys.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthkeys_vrfy:
	${CL} -o ${BUILD}/test_lightkeys_vrfy test_lightkeys_vrfy.c ${BUILD}/lightkeys.o ${BUILD}/lighttools.o -lpthread -lm

test_lighthkeys_write:
	${CL} -o ${BUILD}/test_lightkeys_write test_lightkeys_write.c ${BUILD}/lightkeys.o ${BUILD}/lighttools.o -lpthread -lm

test_lightaes:
	${CL} -o ${BUILD}/test_lightaes test_lightaes.c ${BUILD}/lightaes.o -lpthread -lm

run:
	${BUILD}/test_lightciphers_cbc
	${BUILD}/test_lightciphers_cfb
	#${BUILD}/test_lightcrypto ${BUILD}/ca.key ${BUILD}/ca256.cms
	${BUILD}/test_lighthash3
	${BUILD}/test_lighthash3_big
	${BUILD}/test_lighthash3_shake
	${BUILD}/test_lighthash3_shake_big
	${BUILD}/test_lighthash3_shake_ref
	${BUILD}/test_lightkeys_make
	${BUILD}/test_lightkeys_secr
	${BUILD}/test_lightkeys_sign
	${BUILD}/test_lightkeys_vrfy
	${BUILD}/test_lightkeys_write
	${BUILD}/test_lightaes
