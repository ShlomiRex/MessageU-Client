#pragma once
#include <cstdint>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"
#include "Debug.h"

using namespace std;



class ResponseHeader {
private:
	Version version;				//1 byte
	Code code;						//2 bytes
	PayloadSize payloadSize;		//4 bytes
public:
	ResponseHeader(const char* buffer, size_t buffSize);

	Version getVersion();
	Code getCode();
	PayloadSize getPayloadSize();
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
public:
	InvalidResponseCodeException(int expected_code, int but_got_code) : requested_code(expected_code), got_code(but_got_code) {
	}

	const char* what() const throw ()
	{
		//TODO: Fix creating string on stack!
		string what_str;
		what_str += "Server response code is: " + this->got_code;
		what_str += " but expected code: " + this->requested_code;
		return what_str.c_str();
	}
};
