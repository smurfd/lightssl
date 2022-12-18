clang -c -o lighthash.o ../lighthash.c -fPIC -Wall -pedantic -O3
clang -c -o lighthash3.o ../lighthash3.c -fPIC -Wall -pedantic -O3
clang -c -o lightkeys.o ../lightkeys.c -fPIC -Wall -pedantic -O3
clang -c -o lightcrypto.o ../lightcrypto.c -fPIC -Wall -pedantic -O3
clang -c -o lightciphers.o ../lightciphers.c -fPIC -Wall -pedantic -O3
clang example.c -o example lighthash3.o -Wall -pedantic -O3
./example
rm -f example *.o
