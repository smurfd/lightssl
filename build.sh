rm -rf build
# Build release
cmake -DCMAKE_BUILD_TYPE=Release -Bbuild/release -DCMAKE_C_COMPILER=clang
sh ./src/example/gen_cert.sh
make -Cbuild/release
make -Cbuild/release test

#cmake -DCMAKE_BUILD_TYPE=Debug -Bbuild/debug -DCMAKE_C_COMPILER=clang
#sh ./src/example/gen_cert.sh
#make -Cbuild/debug
#make -Cbuild/debug test
