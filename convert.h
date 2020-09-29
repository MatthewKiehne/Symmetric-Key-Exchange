#pragma once

#ifndef __convert__
#define __convert__

#include <string>
#include<vector>

using namespace std;

class Convert {
public:
	Convert();
	std::string vecToString(vector<char> vec);
	std::string buffToString(char* buf, int bytes);
	std::vector<char> stringToVec(string str, int length);
	int stringToInt(string str);
	long stringToLong(string str);
	std::string intToString(int num);
	std::string longToString(long num);
};

#endif /* defined(__convert__) */