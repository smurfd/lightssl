# First copy this script to your new projects source folder
# Then copy src/*.h to your new projects source folder
# Lastly after you have build lightssl copy build/*.a to your new project source folder.
cp ../src/*.h .
cp ../build/*.a .
clang -o example example.c -llightdefs -llighthash3 -L.
./example
rm lib* light* test* example
