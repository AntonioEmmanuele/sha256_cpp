#Make file for tests..
all:tst

tst: tst.o sha256.o
	g++ -o tst tst.o sha256.o -std=c++2a
tst.o:tst.cpp sha256.cpp
	g++  -c tst.cpp -std=c++2a

sha256.o:sha256.cpp sha256.hpp
	g++  -c sha256.cpp -std=c++2a

clean:
	rm -r -f *.o
	rm tst
