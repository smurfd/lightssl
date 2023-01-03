rm -rf build
CC=clang meson setup build
sh ./src/example/gen_cert.sh
CC=clang ninja -Cbuild
CC=clang ninja -Cbuild test -v -d stats -d explain
