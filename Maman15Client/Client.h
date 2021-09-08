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
#include "Defenitions.h"
#include "Response.h"
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

struct InitSocketException : public exception {
	const char* what() const throw () {
		return "Encountered exception while initializing client socket.";
	}
};

struct Request {
	char clientId[16];
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
	char* payload;
};

class Client
{
private:
	size_t clientVersion;
	char* reqPacket;
	BufferWriter* reqWriter;

	//struct Request request;
	
	boost::asio::io_context* io_context;
	boost::asio::ip::tcp::socket* socket;
	boost::asio::ip::tcp::resolver* resolver;
	boost::asio::ip::tcp::resolver::results_type* endpoints;

	//General request packing functions
	void pack_clientId(const char[16]);
	void pack_version();
	void pack_code(RequestCodes);
	void pack_payloadSize(uint32_t);

	//Send request of reqPacket and size of reqWriter.getOffset()
	size_t sendRequest();
	size_t recvResponse(char* buffer);
public:
	Client(string ip, string port, size_t clientVersion = 1);
	~Client();
	void registerUser(string user);
};


