FLAGS = --todo

all:
	make clean
	make build

build:
	g++ -std=c++11 -O3 -s ./main.cpp -L . -l :libsecp256k1.a -l :keccak256.a -o ./main
	# valgrind --leak-check=yes --quiet ./main
	# ./main

clean:
	rm -f main
	clear
