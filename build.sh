rm -rf build
cmake -DCMAKE_BUILD_TYPE=Release -Bbuild -DCMAKE_C_COMPILER=clang
sh ./src/example/gen_cert.sh
make -Cbuild
make -Cbuild test
