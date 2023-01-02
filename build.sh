rm -rf build
CC=clang meson setup build
sh ./src/example/gen_cert.sh
CC=clang ninja -v -Cbuild
CC=clang ninja -v -Cbuild test -v -d stats -d explain
