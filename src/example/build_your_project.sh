clang -c -o lighthash.o ../lighthash.c -fPIC
clang -c -o lighthash3.o ../lighthash3.c -fPIC
clang -c -o lightkeys.o ../lightkeys.c -fPIC
clang -c -o lightcrypto.o ../lightcrypto.c -fPIC
clang -c -o lightciphers.o ../lightciphers.c -fPIC
clang example.c -o example lighthash3.o
./example
rm -f example *.o
