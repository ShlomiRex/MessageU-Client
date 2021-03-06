#include "Request.h"

#define DEBUG_PREFIX "[Request] "

using namespace std;
using namespace MessageUProtocol;

Request::Request(Version version) : clientVersion(version), writer(S_PACKET_SIZE) {
	
}

Request::~Request() {

}

void Request::pack_version() {
	//uint8_t behaves like 'char'. So convert to int for printing the number itself
	DEBUG("Packing version (1 byte): " << (int)clientVersion);
	writer.write1byte(clientVersion);
}


void Request::pack_clientId(const ClientId& dest_clientId) {
	DEBUG("Packing clientId (" << S_CLIENT_ID << " bytes):");
#ifdef DEBUGGING
	hexify((const unsigned char*)dest_clientId, S_CLIENT_ID);
#endif
	writer.write(dest_clientId, S_CLIENT_ID);
}

void Request::pack_code(RequestCodes code) {
	Code reqCode = static_cast<Code>(code);

	DEBUG("Packing code (2 bytes): " << reqCode);
	writer.write2bytes(reqCode);
}

void Request::pack_payloadSize(PayloadSize size) {
	DEBUG("Packing payload size (4 bytes): " << size);
	writer.write4bytes(size);
}

void Request::pack_payload(const unsigned char* data, size_t size)
{
	DEBUG("Packing payload (" << size << " bytes) :");
#ifdef DEBUGGING
	hexify((const unsigned char*)data, size);
#endif
	writer.write(data, size);
}

void Request::pack_username(string username) {
	DEBUG("Packing name (" << S_USERNAME << " bytes, with null terminator): " << username);
	Username buff = { 0 };
	username.copy((char*)buff, S_USERNAME);
	writer.write(buff, S_USERNAME);
}

void Request::pack_pub_key(const PublicKey& pubkey) {
	DEBUG("Packing public key (" << S_PUBLIC_KEY << " bytes): ");
#ifdef DEBUGGING
	hexify((const unsigned char*)pubkey, S_PUBLIC_KEY);
#endif
	writer.write(pubkey, S_PUBLIC_KEY);
}

void Request::pack_client_id(const ClientId& client_id)
{
	DEBUG("Packing client id (" << S_CLIENT_ID << ") bytes: ");
#ifdef DEBUGGING
	hexify((const unsigned char*)client_id, S_CLIENT_ID);
#endif
	writer.write(client_id, S_CLIENT_ID);
}

void Request::pack_message_header(const MessageHeader& msgHeader)
{
	//Pack client id
	DEBUG("Packing message client id (" << S_CLIENT_ID << " bytes): ");
#ifdef DEBUGGING
	hexify((const unsigned char*)msgHeader.dest_clientId, S_CLIENT_ID);
#endif
	writer.write(msgHeader.dest_clientId, S_CLIENT_ID);

	//Pack Message Type
	MessageType _type = (MessageType)msgHeader.messageType;
	DEBUG("Packing message type (1 byte): " << (int)_type);
	writer.write1byte(_type);

	//Pack Contnet Size
	DEBUG("Packing message content size (4 bytes): " << msgHeader.contentSize);
	writer.write4bytes(msgHeader.contentSize);
}

size_t Request::getPacketSize() {
	return writer.getOffset();
}

const unsigned char* Request::getPacket() {
	return writer.getBuffer();
}
