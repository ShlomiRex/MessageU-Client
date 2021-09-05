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
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

struct InitSocketException : public exception {
	const char* what() const throw () {
		return "Encountered exception while initializing client socket.";
	}
};

class Client
{
private:
	boost::asio::io_context io_context;
public:
	Client(string ip, string port);
};


