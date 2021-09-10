#include "Request.h"

using namespace std;
#define LOG(msg) cout << "[Request] " << msg << endl;

Request::Request(size_t version) : clientVersion(version), writer(S_PACKET_SIZE) {
	
}

Request::~Request() {

}

void Request::pack_version() {
	LOG("Packing version (1 byte): " << this->clientVersion);
	writer.write1byte(clientVersion);
}


void Request::pack_clientId(const char clientId[16]) {
	LOG("Packing clientId (16 bytes):");
	hexify((const unsigned char*)clientId, 16);

	writer.write(clientId, 16);
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
	LOG("Packing name (" << username.size() + 1 << " bytes, with null terminator): " << username);
	writer.write(username.c_str(), username.size());
	writer.write1byte(0); //With null terminator
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