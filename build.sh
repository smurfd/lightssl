if [ -d "src/lightbig" ]; then
    echo "lightbig already cloned"
else
    git clone https://github.com/smurfd/lightbig src/lightbig
fi
meson build
cd build
meson compile
meson test
