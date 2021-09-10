#pragma once

#include <iostream>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"
#include "Utils.h"
#include "OpCodes.h"

class Request {
private:
	uint8_t clientVersion;
	BufferWriter writer;
public:
	Request(uint8_t clientVersion);
	~Request();
	void pack_version();

	void pack_clientId(const char clientId[16]);
	void pack_code(RequestCodes code);
	void pack_payloadSize(uint32_t size);
	void pack_username(std::string username);
	void pack_pub_key(const char pubkey[S_PUBLIC_KEY]);
	size_t getPacketSize();
	const char* getPacket();
};