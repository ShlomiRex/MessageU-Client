#pragma once

#include <iostream>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"
#include "Utils.h"
#include "OpCodes.h"

class Request {
private:
	Version clientVersion;
	BufferWriter writer;
public:
	Request(Version clientVersion);
	~Request();

	void pack_clientId(const ClientId client_id);
	void pack_version();
	void pack_code(RequestCodes code);
	void pack_payloadSize(PayloadSize size);

	//Generic function to pack and append to payload.
	void pack_payload(const char* data, size_t size);

	//Spesific request packing
	void pack_username(std::string username);				//username size can be any size. This function will right pad with zeros.
	void pack_pub_key(const PublicKey pubkey);
	void pack_client_id(const ClientId client_id);

	size_t getPacketSize();
	const char* getPacket();
};