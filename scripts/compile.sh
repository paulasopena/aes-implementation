cd ..

cd build

rm -r main

cd ..

cd src

gcc -Wall -Wextra -o ../build/main main.c

cd ..

cd build

./main
