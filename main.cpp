#include <iostream>
#include <string.h>
#include "blowfish.h"

using namespace std;
typedef unsigned char byte;

int main()
{
	//making a key (must be a multiple of 8)
	vector<char> key;
	for (int i = 0; i < 24; i++) {
		key.push_back(i * 3);
	}

	//makeing the blowfish with the made key
	Blowfish blow(key);
	cout << key.size() << endl;

	//text to be encrypted
	string text("well idk uwec is the best! :)");
	vector<char> src(text.begin(), text.end());

	//prints out the text
	for (std::vector<char>::const_iterator i = src.begin(); i != src.end(); ++i) {
		std::cout << *i;
	}

	cout << endl;

	//decodes the encrypted
	vector<char> enc = blow.Encrypt(src);

	//prints the decrypted
	for (std::vector<char>::const_iterator i = enc.begin(); i != enc.end(); ++i) {
		std::cout << *i << ' ';
	}

	//prints out the size of the encrypted and decrypted vectors
	cout << endl;
	cout << src.size() <<  " " << enc.size() << endl;


	//decodes
	vector<char> dec = blow.Decrypt(enc);

	//prints out he decrypted
	for (std::vector<char>::const_iterator i = dec.begin(); i != dec.end(); ++i) {
		std::cout << *i;
	}

	cout << endl << dec.size() << endl;

	return 1;
}