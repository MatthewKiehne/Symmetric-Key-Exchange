#include <string>
#include <vector>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>

#include "convert.h"

using namespace std;

Convert::Convert() {}

string Convert::vecToString(vector<char> vec) {
	string s(vec.begin(), vec.end());
	return s;
}
string Convert::buffToString(char* buf, int bytes) {
	string part(buf, 0, bytes);
	return part;
}
vector<char> Convert::stringToVec(string str, int length) {
	vector<char> result;
	for (int i = 0; i < length; i++) {
		result.push_back(str.at(i));
	}
	return result;
}
int Convert::stringToInt(string str) {
	return atoi(str.c_str());
}
long Convert::stringToLong(string str) {
	return atol(str.c_str());
}
string Convert::intToString(int num) {
	
	ostringstream outStream;
	// Sending a number as a stream into output 
	// string 
	outStream << num;
	// the str() coverts number into string 
	string geek = outStream.str();
	return geek;
}
string Convert::longToString(long num) {
	ostringstream outStream;
	// Sending a number as a stream into output 
	// string 
	outStream << num;
	// the str() coverts number into string 
	string geek = outStream.str();
	return geek;
}