#include "Response.h"

Response::Response(const char* buff, size_t buffSize) {
	BufferReader reader(buff, buffSize);
	this->version = reader.read1byte();
	this->code = reader.read2bytes();
	this->payloadSize = reader.read4bytes();

	this->payload = new char[S_PACKET_SIZE];
	reader.read(this->payloadSize, this->payload, S_PACKET_SIZE);
}

Response::~Response() {
	delete[] payload;
}

uint8_t Response::getVersion() {
	return this->version;
}

uint16_t Response::getCode() {
	return this->code;
}

uint32_t Response::getPayloadSize() {
	return this->payloadSize;
}

const char* Response::getPayload() {
	return (const char*)this->payload;
}

