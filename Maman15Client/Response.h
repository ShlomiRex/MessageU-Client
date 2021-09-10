#pragma once
#include <cstdint>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"

using namespace std;

class Response
{
private:
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
	char* payload;

public:
	Response(const char* buffer, size_t buffSize);
	~Response();

	uint8_t getVersion();
	uint16_t getCode();
	uint32_t getPayloadSize();
	const char* getPayload();
};

