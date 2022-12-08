CC=clang meson setup build
sh src/example/gen_cert.sh
CC=clang ninja -C build
CC=clang ninja -C build test -v -d stats -d explain
