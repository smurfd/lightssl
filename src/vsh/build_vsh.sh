mkdir -p build
clang -std=c99 -pedantic -O2 -lm -pthread vsh_cli.c vsh.c -o build/cli
clang -std=c99 -pedantic -O2 -lm -pthread vsh_srv.c vsh.c -o build/srv

echo "run ./build/srv in one terminal"
echo "run ./build/cli in another terminal"
