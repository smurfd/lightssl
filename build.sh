if [ -d "src/lightbig" ]; then
    echo "lightbig already cloned"
    cd src/lightbig
    git pull
    cd ../..
else
    git clone https://github.com/smurfd/lightbig src/lightbig
fi
CC=clang
meson build
cd build
meson compile
meson test
