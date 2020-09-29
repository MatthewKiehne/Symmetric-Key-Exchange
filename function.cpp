#include "function.h"
#include <iostream>

using namespace std;
Function::Function() {}

long Function::func(long value) {
	long result = value + value;
	cout << "in func " << result << endl;
	return result;
}

long Function::nonce(long nonce) {
	const long A = 48271;
	const long M = 2147483647;
	const long Q = M / A;
	const long R = M % A;

	static long state = 1;
	long t = A * (state % Q) - R * (state / Q);

	if (t > 0) {
		state = t;
	} else {
		state = t + M;
	}
	return (long)(((double)state / M)* nonce);
}