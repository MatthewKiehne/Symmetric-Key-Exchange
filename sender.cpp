#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <cstdlib>
#include <sstream>

#include "blowfish.h"
#include "function.h"
#include "convert.h"

using namespace std;

int main()
{

	Convert con;

	//gets the public key for reciever
	string recPublicKeyStr;
	cout << "Public key for reciever> ";
	getline(cin, recPublicKeyStr);

	int recKeyNumZeros = 8 - (recPublicKeyStr.length() % 8);
	for (int i = 0; i < recKeyNumZeros; i++) {
		recPublicKeyStr = recPublicKeyStr + "0";
	}
	vector<char> recPublicKeyVec = con.stringToVec(recPublicKeyStr, recPublicKeyStr.length());

	cout << "Padded public reciever key: " << recPublicKeyStr << endl;

	//	Create a socket and connect to the reciever
	int recieverSock= socket(AF_INET, SOCK_STREAM, 0);
	if (recieverSock== -1)
	{
		return 1;
	}
	int port = 9801;
	string ipAddressReciever = "10.35.195.22";
	sockaddr_in hitReciever;
	hitReciever.sin_family = AF_INET;
	hitReciever.sin_port = htons(port);
	inet_pton(AF_INET, ipAddressReciever.c_str(), &hitReciever.sin_addr);
	int connectRes = connect(recieverSock, (sockaddr*)&hitReciever, sizeof(hitReciever));
	if (connectRes == -1)
	{
		return 1;
	}

	//sets data out
	char bufArray[4096];
	string userInput;

	//public key of responder
	vector<char> recKey;
	for (int i = 0; i < 24; i++) {
		recKey.push_back(i * 3);
	}

	//makeing the blowfish with public key of responder
	Blowfish blow(recPublicKeyVec);

	//making a the session key
	vector<char> sesKey;
	for (int i = 0; i < 8; i++) {
		sesKey.push_back(i * 9);
	}
	string sesStr(sesKey.begin(), sesKey.end());
	cout << "Session Key: " << sesStr << endl;

	//making message for step 3
	string idA("10.35.195.47");
	string firstMessage = sesStr + idA;
	cout << "Session Key and ID: " << firstMessage << endl;
	vector<char> src = con.stringToVec(firstMessage, firstMessage.length());

	//encrypting step 3
	vector<char> encVec = blow.Encrypt(src);
	string encStr = con.vecToString(encVec);
	
	// sending step 3
	cout << "sent: " << encStr << endl;
	int sendRes = send(recieverSock, encStr.c_str(), encStr.size() + 1, 0);
	if (sendRes == -1)
	{
		cout << "Could not send to server! Whoops!\r\n";
		return -1;
	}

	//Wait for response
	memset(bufArray, 0, 4096);
	int bytesReceived = recv(recieverSock, bufArray, 4096, 0);
	if (bytesReceived == -1)
	{
		cout << "There was an error getting response from server\r\n";
		return -1;
	}



	//		Display response
	string recStr = con.buffToString(bufArray, bytesReceived);
	cout << "recieved: " << recStr << endl;
	vector<char> recVec = con.stringToVec(recStr, recStr.length());

	/*
	cout << "printing out session key as ints" << endl;
	for (int i = 0; i < sesStr.length(); i++) {
		cout << +(sesStr.at(i)) << " ";
	}
	
	cout << endl;

	for (int i = 0; i < sesKey.size(); i++) {
		cout << +(sesKey.at(i)) << " ";
	}
	cout << endl;
	*/

	//got key from step 2
	Blowfish sessionBlow(sesKey);

	//decrypt step 4
	vector<char> decVec = sessionBlow.Decrypt(recVec);
	string decStr = con.vecToString(decVec);

	cout << "Decrypted String: " << decStr << " " << decStr.length() << endl;

	//get nonce from step 4
	long beforeFunction = con.stringToLong(decStr);

	cout << "before function: " << beforeFunction << endl;

	//apply to function to the nance for step 5
	Function function;
	long afterFunction = function.func(beforeFunction);
	string geek = con.longToString(afterFunction);

	cout << "after function:" << afterFunction << endl;
	/*
	// declaring output string stream 
	ostringstream str1;

	// Sending a number as a stream into output 
	// string 
	str1 << afterFunction;
	// the str() coverts number into string 
	*/
	
	//encrypt for step 5
	vector<char> aftFuncVec = con.stringToVec(geek, geek.length());
	vector<char> aftFuncEnc = sessionBlow.Encrypt(aftFuncVec);
	string aftEncStr = con.vecToString(aftFuncEnc);

	cout << "after function encryption: " << aftEncStr << " " << aftEncStr.size() << endl;
	/*
	//prints out the text
	for (std::vector<char>::const_iterator i = aftFuncEnc.begin(); i != aftFuncEnc.end(); ++i) {
		std::cout << +(*i) << " ";
	}
	cout << endl;
	*/

	//step 5 send to reciever
	sendRes = send(recieverSock, aftEncStr.c_str(), aftEncStr.size(), 0);
	if (sendRes == -1)
	{
		cout << "Could not send to server! Whoops!\r\n";
	}

	//	Close the socket
	close(recieverSock);

	return 0;
}