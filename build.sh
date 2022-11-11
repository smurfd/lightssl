CC=clang meson setup build
CC=clang ninja -C build
CC=clang ninja -C build test -v -d stats -d explain
