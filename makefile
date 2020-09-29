all: main kdc sender reciever clean

main: main.o blowfish.o
	g++ -o main main.o blowfish.o

kdc: kdc.o blowfish.o
	g++ -o kdc kdc.o blowfish.o

sender: sender.o blowfish.o function.o convert.o
	g++ -o sender sender.o blowfish.o function.o convert.o

reciever: reciever.o blowfish.o function.o convert.o
	g++ -o reciever reciever.o blowfish.o function.o convert.o

main.o:
	g++ -c main.cpp

blowfish.o:
	g++ -c blowfish.cpp

kdc.o:
	g++ -c kdc.cpp

sender.o:
	g++ -c sender.cpp

reciever.o:
	g++ -c reciever.cpp

function.o:
	g++ -c function.cpp

convert.o:
	g++ -c convert.cpp

clean:
	rm -f *~
	rm -f *.o