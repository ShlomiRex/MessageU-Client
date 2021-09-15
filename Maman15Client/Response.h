#pragma once
#include <cstdint>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"

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

};

struct InvalidResponseCodeException : public std::exception {

};