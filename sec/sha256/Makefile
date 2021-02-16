#Make file for tests..
all:start

start: tst.o sha256.o
	g++ -o tst tst.o sha256.o
tst.o:tst.cpp sha256.cpp
	g++  -c tst.cpp

sha256.o:sha256.cpp sha256.hpp
	g++  -c sha256.cpp

clean:
	rm -r -f *.o
	rm start
