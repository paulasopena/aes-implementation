cd ..

cd /kattis/build

rm -r main

cd ..

gcc -Wall -Wextra -o ../build/main main.c

cd ..

cd build

./main
