# First copy this script to your new projects source folder
# Then copy src/*.h to your new projects source folder
# Lastly after you have build lightssl copy build/*.a to your new project source folder.

gcc -o main main.c -llightssl -llightdefs -llighthash -L.
