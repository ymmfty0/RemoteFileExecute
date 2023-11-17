#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <stdio.h>
#include <vector>


#pragma comment (lib, "Ws2_32.lib")

class TCPClient {
private:

	int DEFAULT_BUFLEN = 512;
	SOCKET clientSocket;
	std::vector<char> recvbuff;

public:
	TCPClient();
	~TCPClient();

	bool connectToServer(const char* serverIp, short port);
	bool sendToServer(const std::string& data);

	int reciveData();
	
	std::vector<char> getBuffer();
	void setBufLen(int bufLen);

};