#include "Response.h"

using namespace std;

ResponseHeader::ResponseHeader(const char* buffer, size_t buffSize) {
	if (buffSize < S_RESPONSE_HEADER) {
		throw exception("Can't reconstruct response header: buffer size is too low.");
	}

	BufferReader reader(buffer, buffSize);
	this->version = reader.read1byte();
	this->code = reader.read2bytes();
	this->payloadSize = reader.read4bytes();
}

uint8_t ResponseHeader::getVersion() {
	return version;
}
uint16_t ResponseHeader::getCode() {
	return code;
}
uint32_t ResponseHeader::getPayloadSize() {
	return payloadSize;
}



// ==============================================================================

