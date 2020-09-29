#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <bits/stdc++.h> 
#include <cstdlib>

#include "blowfish.h"
#include "function.h"
#include "convert.h"

using namespace std;

int main()
{
	//makes a convert for all the conversions
	Convert con;

	//gets the public key for reciever
	string recPublicKeyStr;
	cout << "Public key for reciever> ";
	getline(cin, recPublicKeyStr);

	int recKeyNumZeros = 8 - (recPublicKeyStr.length() % 8);
	for (int i = 0; i < recKeyNumZeros; i++) {
		recPublicKeyStr = recPublicKeyStr + "0";
	}
	vector<char> recPublicKeyVec(recPublicKeyStr.begin(), recPublicKeyStr.end());

	//gets the random number from the user
	string senderRandomNumber;
	cout << "Random number for Sender> ";
	getline(cin, senderRandomNumber);

	// Create a socket
	int listening = socket(AF_INET, SOCK_STREAM, 0);
	if (listening == -1) {
		cerr << "Can't create a socket! Quitting" << endl;
		return -1;
	}
	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(9801);
	inet_pton(AF_INET, "10.35.195.22", &hint.sin_addr);
	bind(listening, (sockaddr*)&hint, sizeof(hint));

	// gets the client
	listen(listening, SOMAXCONN);
	sockaddr_in client;
	socklen_t clientSize = sizeof(client);
	int clientSocket = accept(listening, (sockaddr*)&client, &clientSize);
	char host[NI_MAXHOST];      // Client's remote name
	char service[NI_MAXSERV];   // Service (i.e. port) the client is connect on
	memset(host, 0, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);
	memset(service, 0, NI_MAXSERV);
	if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
	{
		cout << host << " connected on port " << service << endl;
	}
	else
	{
		inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
		cout << host << " connected on port " << ntohs(client.sin_port) << endl;
	}

	// Close listening socket
	close(listening);

	// data for the sockets
	char buf[4096];
	memset(buf, 0, 4096);

	// recieving from step 3
	int bytesReceived = recv(clientSocket, buf, 4096, 0);
	if (bytesReceived == -1)
	{
		cerr << "Error in recv(). Quitting" << endl;
		return -1;
	}
	
	// decrypting setp 3
	Blowfish blow(recPublicKeyVec);
	string recEncStr(buf, 0, bytesReceived);
	vector<char> recEncVec(recEncStr.begin(), recEncStr.end());
	vector<char> decVec = blow.Decrypt(recEncVec);
	string decStr(decVec.begin(), decVec.end());
	cout << "Decrypted String: " << decStr << endl;

	//removing the ID from step 3
	string delimiter = "10.35.195.47";
	int delPos = decStr.find(delimiter);
	cout << "pos: " << delPos << endl;
	if (delPos == -1) {
		cout << "invalid ID" << endl;
		return -1;
	}

	//gets the session key from step 3
	string token = decStr.substr(0, decStr.find(delimiter));
	cout << "session key: " << token << endl;
	vector<char> sessionKey(token.begin(), token.end());

	//creates a blowfish from the key from step 3
	Blowfish sessionBlow(sessionKey);

	cout << "sender Random number: " << senderRandomNumber << " " << senderRandomNumber.length() << endl;

	//getting the f(nonce)
	Function fun;

	long nonce = con.stringToLong(senderRandomNumber);

	cout << "nonce: " << nonce << endl;
	long funNonce = fun.func(nonce);
	cout << "function nonce: " << funNonce << endl;
	string nonceStr = con.longToString(nonce);

	//encrypting the nonce for step 4
	vector<char> conVec = con.stringToVec(nonceStr, nonceStr.length());
	vector<char> encConVec = sessionBlow.Encrypt(conVec);
	string encConStr(encConVec.begin(), encConVec.end());
	cout << "encyption length: " << encConStr.length() << endl;
	cout << "sent back encypttion: " << encConStr << endl;


	//sending the encrypted nonce for step 4
	memset(buf, 0, 4096);
	strcpy(buf, encConStr.c_str());
	send(clientSocket, buf, encConStr.length(), 0);

	//recieve step 5
	cout << "erase buffer" << endl;
	memset(buf, 0, 4096);
	bytesReceived = recv(clientSocket, buf, 4096, 0);
	if (bytesReceived == -1)
	{
		cerr << "Error in recv(). Quitting" << endl;
		return -1;
	}
	string afterFunc(buf, 0, bytesReceived);
	cout << "recieved num bytes: " << bytesReceived << endl;
	cout << "recieved enc: " << afterFunc << "     " << afterFunc.length() << endl;
	vector<char> afterFunEncVec;
	for (int i = 0; i < bytesReceived; i++) {

		cout << +(buf[i]) << " ";
		afterFunEncVec.push_back(buf[i]);
	}
	cout << endl;
	cout << "enc length: " << afterFunEncVec.size() << endl;

	//decrypt step 5
	vector<char> afterFunDecVec = sessionBlow.Decrypt(afterFunEncVec);
	cout << "dec length: " << afterFunDecVec.size() << endl;
	string afterFunDecStr(afterFunDecVec.begin(), afterFunDecVec.end());
	cout << afterFunDecStr << endl;
	long longAfterFun = con.stringToLong(afterFunDecStr);
	
	if (longAfterFun == funNonce) {
		cout << "yes" << endl;
	}
	else {
		cout << "no" << endl;
	}

	// Close the socket
	close(clientSocket);

	return 0;
}