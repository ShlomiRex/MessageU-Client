#include "MessageRequest.h"

#define DEBUG_PREFIX "[MessageRequest] "

using namespace std;
using namespace MessageUProtocol;

MessageRequest::MessageRequest(MessageHeader header) : header(header), messageContent(nullptr) {

}

const char* MessageRequest::pack(ContentSize* result_size) const {
	*result_size = S_MESSAGE_HEADER + header.contentSize;

	char* result_payload = new char[*result_size];
	BufferWriter writer(result_payload, *result_size);

	//Write header
	DEBUG("Packing message header (" << S_MESSAGE_HEADER << " bytes)");
	writer.write(header.dest_clientId, S_CLIENT_ID);
	writer.write1byte(header.messageType);
	writer.write4bytes(header.contentSize);

	//Write message content
	if (header.contentSize != 0) {
		DEBUG("Packing message content (" << header.contentSize << " bytes): ");
#ifdef DEBUGGING
		hexify((const unsigned char*)messageContent, header.contentSize);
#endif
		writer.write(messageContent, header.contentSize);
	}

	return result_payload;
}
