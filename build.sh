rm -rf build
cmake -DCMAKE_BUILD_TYPE=Release -Bbuild -DCMAKE_C_COMPILER=clang
sh ./src/example/gen_cert.sh
make -Cbuild
make -Cbuild test

# preparing separate release and debug build
#cmake -DCMAKE_BUILD_TYPE=Release -Bbuild/release -DCMAKE_C_COMPILER=clang
#sh ./src/example/gen_cert.sh
#make -Cbuild/release
#make -Cbuild/release test

#cmake -DCMAKE_BUILD_TYPE=Debug -Bbuild/debug -DCMAKE_C_COMPILER=clang
#sh ./src/example/gen_cert.sh
#make -Cbuild/debug
#make -Cbuild/debug test
