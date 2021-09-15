#pragma once

#include "ProtocolDefenitions.h"
#include "BufferUtils.h"
#include <iostream>
#include "Utils.h"

//Packed size
#define S_MESSAGE_HEADER 21
typedef struct {
	ClientId clientId;
	MessageType messageType;
	ContentSize contentSize;
} MessageHeader;


class MessageRequest
{
private:
	MessageHeader header;
	char* messageContent;
public:
	MessageRequest(MessageHeader header);

	//Return bytes, as you would for sending this message object. For request payload.
	const char* pack(ContentSize* result_size) const;
};

