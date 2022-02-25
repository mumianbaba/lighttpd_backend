rm build -rf
mkdir build
cd build
cmake .. -DWITH_PCRE=OFF -DWITH_DBI=ON -DCMAKE_INSTALL_PREFIX=$PWD/__install

gcc -c ../src/lemon.c -o ./build/CMakeFiles/lemon.dir/lemon.c.o
gcc ./build/CMakeFiles/lemon.dir/lemon.c.o -o build/lemon 

make
