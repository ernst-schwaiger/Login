CC=g++
#use for debugging and for getting the password hash
#CCOPTS=-ggdb3 -O0 -DDEBUG -Wall
# production use, faster
CCOPTS= -O2 -Wall
all: login

login: main.o Hasher.o Auth.o
	$(CC) $(CCOPTS) main.o Hasher.o Auth.o -o login -lssl -lcrypto

main.o: main.cpp Hasher.h Auth.h
	$(CC) -c $(CCOPTS) main.cpp -o main.o

Hasher.o: Hasher.cpp Hasher.h
	$(CC) -c $(CCOPTS) Hasher.cpp -o Hasher.o

Auth.o: Auth.cpp Auth.h Hasher.h
	$(CC) -c $(CCOPTS) Auth.cpp -o Auth.o

clean:
	rm -f login  *.o
