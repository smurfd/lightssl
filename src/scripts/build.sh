# Run ./src/scripts/build.sh from source root
rm -rf build
mkdir -p build/debug build/release
# Build release
cmake -DCMAKE_BUILD_TYPE=Release -Bbuild/release -DCMAKE_C_COMPILER=clang
sh ./src/scripts/gen_cert_release.sh
make -Cbuild/release
make -Cbuild/release test
# Build debug, here asserts work
cmake -DCMAKE_BUILD_TYPE=Debug -Bbuild/debug -DCMAKE_C_COMPILER=clang
sh ./src/scripts/gen_cert_debug.sh
make -Cbuild/debug
make -Cbuild/debug test
