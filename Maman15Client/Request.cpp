#include "Request.h"

using namespace std;
#define LOG(msg) cout << "[Request] " << msg << endl;

Request::Request(uint8_t version) : clientVersion(version), writer(S_PACKET_SIZE) {
	
}

Request::~Request() {

}

void Request::pack_version() {
	//uint8_t behaves like 'char'. So convert to int for printing the number itself
	LOG("Packing version (1 byte): " << (int)clientVersion);
	writer.write1byte(clientVersion);
}


void Request::pack_clientId(const char clientId[S_CLIENT_ID]) {
	LOG("Packing clientId (" << S_CLIENT_ID << " bytes):");
	hexify((const unsigned char*)clientId, S_CLIENT_ID);

	writer.write(clientId, S_CLIENT_ID);
}

void Request::pack_code(RequestCodes code) {
	uint16_t reqCode = static_cast<uint16_t>(code);

	LOG("Packing code (2 bytes): " << reqCode);
	writer.write2bytes(reqCode);
}

void Request::pack_payloadSize(uint32_t size) {
	LOG("Packing payload size (4 bytes): " << size);
	writer.write4bytes(size);
}

void Request::pack_username(string username) {
	LOG("Packing name (" << S_USERNAME << " bytes, with null terminator): " << username);
	char buff[S_USERNAME] = { 0 };
	username.copy(buff, S_USERNAME);
	writer.write(buff, S_USERNAME);
}

void Request::pack_pub_key(const char pubkey[S_PUBLIC_KEY]) {
	LOG("Packing public key (" << S_PUBLIC_KEY << " bytes): ");
	hexify((const unsigned char*)pubkey, S_PUBLIC_KEY);
	writer.write(pubkey, S_PUBLIC_KEY);
}

size_t Request::getPacketSize() {
	return writer.getOffset();
}

const char* Request::getPacket() {
	return writer.getBuffer();
}