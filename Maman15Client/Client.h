#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <stdio.h>
#include <exception>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "OpCodes.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <iomanip>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"
#include "Response.h"
#include "Request.h"
#include "Utils.h"
#include <algorithm>
#include "FileManager.h"
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

struct InitSocketException : public exception {
	const char* what() const throw () {
		return "Encountered exception while initializing client socket.";
	}
};

//Client holds a single request buffer. Because the protocol is stateless, we only send ONE request, per client object.
//The responses, however, can be more than 1 packet.
class Client
{
private:
	Request request;
	
	boost::asio::io_context* io_context;
	boost::asio::ip::tcp::socket* socket;
	boost::asio::ip::tcp::resolver* resolver;
	boost::asio::ip::tcp::resolver::results_type* endpoints;

	//Sends this class's request object.
	size_t sendRequest();

	//Receive response header (fixed size). 
	ResponseHeader recvResponseHeader(ResponseCodes requiredCode);
	
	//General function to receive required amount of bytes in socket.
	const char* recvNextPayload(uint32_t amountRecvBytes);

	//Spesific recv functions
	Response_UsetList recvNextUserInList();
	void recvClientId(ClientId result);
	void recvUsername(Username result);

public:
	Client(string ip, string port, Version clientVersion = 1);
	~Client();

	void registerUser(string user);
	void getClients();
	void getPublicKey(ClientId client_id, PublicKey result_pub_key);
};


