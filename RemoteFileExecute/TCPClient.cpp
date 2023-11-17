#include "TCPClient.h"
#include <algorithm>

// Constructor
TCPClient::TCPClient() : clientSocket(INVALID_SOCKET) , recvbuff(DEFAULT_BUFLEN)
{
	// Initializing Winsock 
	// https://learn.microsoft.com/ru-ru/windows/win32/winsock/initializing-winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		printf("[!] Failed to initialize Winsock\n");
		exit(EXIT_FAILURE);
	}
}

// Desctructor
TCPClient::~TCPClient()
{
	// Checking the socket for correct initialization
	if (clientSocket != INVALID_SOCKET) {
		closesocket(clientSocket);
	}
	// cleanup 
	WSACleanup();
}

// Connecting to the server 
bool TCPClient::connectToServer(const char* serverIp, short port)
{
	// Creating tcp socket
	// AF-INET - indicates that we will use ipv4
	// SOCK_STREAM - indicates the use of data streaming, which is used in TCP
	// IPPROTO_TCP - explicitly specifying the use of the TCP protocol
	clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (clientSocket == INVALID_SOCKET) {
		printf("[!] Error creating socket\n");
		return false;
	}

	// Structure for specifying address and port
	SOCKADDR_IN addr;

	// Specify the address family for our IP 
	// The value of the sin_family field is always AF_INET
	addr.sin_family = AF_INET;

	// Specify the port 
	addr.sin_port = htons(port);

	// Convert IPv4 from text to its binary representation
	InetPtonA(AF_INET, serverIp, &addr.sin_addr.s_addr);

	// Connecting to the server
	int iResult = connect(clientSocket, (SOCKADDR*)(&addr), sizeof(addr));
	if (iResult != 0) {
		printf("[!] Error connection to server\n");
		closesocket(clientSocket);
		return false;
	}

	return true;
}

// Send message to server
bool TCPClient::sendToServer(const std::string& data)
{
	// The send function sends data to the connected socket.
	int iResult = send(clientSocket, data.c_str(), data.length(), 0);
	if (iResult == SOCKET_ERROR) {
		// Receiving an error code after a network operation
		int error = WSAGetLastError();
		printf("[!] Error sending to server. Error code: %d\n", error);

		return false;
	}
	printf("[+] Bytes Sent: %i\n", iResult);
	
	return true;
}


// Receiving data from TCP server
int TCPClient::reciveData()
{

	// Stores the result of a message received from the server 
	int iResult;

	// Check whether the array is filled with zeros or not 
	bool hasZeros = std::all_of(recvbuff.begin(), recvbuff.end(), [](int i) { return i == 0; });

	// If it's not filled out
	if (!hasZeros) {

		// Clearing arrays
		recvbuff.clear();

		// Resize the array
		// This is necessary if the received message 
		// has a size larger than the default value, which is 512. 
		recvbuff.resize(DEFAULT_BUFLEN);
	}
	// Receiving a message
	iResult = recv(clientSocket, recvbuff.data(), recvbuff.size(), 0);

	if (iResult > 0) {
		printf("[+] Bytes received: %d\n", iResult);
	}
	else if (iResult == 0) {
		printf("[-] Connection closed\n");
		return 0;
	}
	else {
		printf("[!] recv failed: %d\n", WSAGetLastError());
		return -1;
	}
	
	 return iResult;
}

// Getter for buffer
std::vector<char> TCPClient::getBuffer()
{
	return recvbuff;
}

// Setter for set DEAFULT_BUFLEN
void TCPClient::setBufLen(int bufLen)
{
	this->DEFAULT_BUFLEN = bufLen;
}
