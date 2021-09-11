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
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include "Request.h"
#include "Utils.h"
#include <algorithm>
#include <boost/algorithm/hex.hpp>
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

	size_t sendRequest();
	//Returns new Response object from server
	//If 'with_payload' is false, recv only 7 bytes (header only).
	//Else, recv S_PACKET_SIZE bytes.
	Response* recvResponse(bool with_payload = true); 

	//Saving registeration information
	void saveRegInfo(string username, const char clientId[S_CLIENT_ID]);

	string getSavedUsername();
	void getSavedClientId(char buffer[S_CLIENT_ID]);
	const char* getSavedPrivateKey();

public:
	Client(string ip, string port, uint8_t clientVersion = 1);
	~Client();
	void registerUser(string user);
	void getClients();
};


