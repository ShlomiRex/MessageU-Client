#pragma once

#include "ProtocolDefenitions.h"
#include "BufferUtils.h"
#include <iostream>
#include "Utils.h"
#include "Debug.h"

//using namespace MessageUProtocol; //bad practice

//Packed size
#define S_MESSAGE_HEADER 21
typedef struct {
	MessageUProtocol::ClientId dest_clientId;
	MessageUProtocol::MessageType messageType;
	MessageUProtocol::ContentSize contentSize;
} MessageHeader;


class MessageRequest
{
private:
	MessageHeader header;
	char* messageContent;
public:
	MessageRequest(MessageHeader header);

	//Return bytes, as you would for sending this message object. For request payload.
	const unsigned char* pack(MessageUProtocol::ContentSize* result_size) const;
};

