clang -c -o lighthash.o ../src/lighthash.c -fPIC
clang -c -o lighthash3.o ../src/lighthash3.c -fPIC
clang -c -o lightkeys.o ../src/lightkeys.c -fPIC
clang -c -o lightcrypto.o ../src/lightcrypto.c -fPIC
clang -c -o lightciphers.o ../src/lightciphers.c -fPIC
clang example.c -o example lighthash3.o
./example
rm -f example *.o
