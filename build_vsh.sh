mkdir -p build
clang -std=c99 -pedantic -O2 -lm -pthread src/vsh_cli.c src/vsh.c -o build/cli
clang -std=c99 -pedantic -O2 -lm -pthread src/vsh_srv.c src/vsh.c -o build/srv

echo "run ./build/srv in one terminal"
echo "run ./build/cli in another terminal"
