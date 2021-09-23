#pragma once

#include <iostream>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"
#include "Utils.h"
#include "Debug.h"
#include "MessageRequest.h"

class Request {
private:
	MessageUProtocol::Version clientVersion;
	BufferWriter writer;
public:
	Request(MessageUProtocol::Version clientVersion);
	~Request();

	//Common header fields
	void pack_clientId(const MessageUProtocol::ClientId& client_id);
	void pack_version();
	void pack_code(MessageUProtocol::RequestCodes code);
	void pack_payloadSize(MessageUProtocol::PayloadSize size);

	//Generic function to pack and append to payload.
	void pack_payload(const unsigned char* data, size_t size);

	//Spesific request packing
	void pack_username(std::string username);				//username size can be any size. This function will right pad with zeros.
	void pack_pub_key(const MessageUProtocol::PublicKey& pubkey);
	void pack_client_id(const MessageUProtocol::ClientId& client_id);

	//Message packing
	void pack_message_header(const MessageHeader& msgHeader);
	//To pack message content, just pack payload.

	size_t getPacketSize();
	const unsigned char* getPacket();
};