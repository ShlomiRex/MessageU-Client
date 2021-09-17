#include "Request.h"

#define DEBUG_PREFIX "[Request] "

using namespace std;

Request::Request(Version version) : clientVersion(version), writer(S_PACKET_SIZE) {
	
}

Request::~Request() {

}

void Request::pack_version() {
	//uint8_t behaves like 'char'. So convert to int for printing the number itself
	DEBUG("Packing version (1 byte): " << (int)clientVersion);
	writer.write1byte(clientVersion);
}


void Request::pack_clientId(const ClientId clientId) {
	DEBUG("Packing clientId (" << S_CLIENT_ID << " bytes):");
#ifdef DEBUGGING
	hexify((const unsigned char*)clientId, S_CLIENT_ID);
#endif
	writer.write(clientId, S_CLIENT_ID);
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

void Request::pack_payload(const char* data, size_t size)
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
	username.copy(buff, S_USERNAME);
	writer.write(buff, S_USERNAME);
}

void Request::pack_pub_key(const PublicKey pubkey) {
	DEBUG("Packing public key (" << S_PUBLIC_KEY << " bytes): ");
#ifdef DEBUGGING
	hexify((const unsigned char*)pubkey, S_PUBLIC_KEY);
#endif
	writer.write(pubkey, S_PUBLIC_KEY);
}

void Request::pack_client_id(const ClientId client_id)
{
	DEBUG("Packing client id (" << S_CLIENT_ID << ") bytes: ");
#ifdef DEBUGGING
	hexify((const unsigned char*)client_id, S_CLIENT_ID);
#endif
	writer.write(client_id, S_CLIENT_ID);
}

size_t Request::getPacketSize() {
	return writer.getOffset();
}

const char* Request::getPacket() {
	return writer.getBuffer();
}

void Request::pack_message_type(MessageTypes type) {
	//Convert enum type to required size
	MessageType _type = (MessageType)type;
	DEBUG("Packing message type (1 bytes): " << _type);
	writer.write1byte(_type);
}

void Request::pack_content_size(ContentSize size) {
	DEBUG("Packing content size (4 bytes): " << size);
	writer.write4bytes(size);
}