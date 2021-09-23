#pragma once
#include <cstdint>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"
#include "Debug.h"

//using namespace std; //bad practice
//using namespace MessageUProtocol; //bad practice

class ResponseHeader {
private:
	MessageUProtocol::Version version;				//1 byte
	MessageUProtocol::Code code;					//2 bytes
	MessageUProtocol::PayloadSize payloadSize;		//4 bytes
public:
	ResponseHeader(const unsigned char* buffer, size_t buffSize);

	MessageUProtocol::Version getVersion();
	MessageUProtocol::Code getCode();
	MessageUProtocol::PayloadSize getPayloadSize();
};



struct ResponseErrorException : public std::exception {
	const char* what() const throw ()
	{
		return "Got ERROR response from server.";
	}
};

struct InvalidResponseCodeException : public std::exception {
private:
	int requested_code;
	int got_code;

	std::string mystr;
public:
	InvalidResponseCodeException(int expected_code, int but_got_code) : requested_code(expected_code), got_code(but_got_code) {
		mystr += "Server response code is: " + this->got_code;
		mystr += " but expected code: " + this->requested_code;
	}

	const char* what() const throw ()
	{
		return mystr.c_str();
	}
};
