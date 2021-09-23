#include "BufferUtils.h"

using namespace std;

BufferWriter::BufferWriter(unsigned char* buffer, size_t bufferSize) :
    buffer(buffer), offset(0), bufferSize(bufferSize), isInternalBuffer(false) {
    memset(buffer, 0, bufferSize);
}

BufferWriter::BufferWriter(size_t bufferSize) : bufferSize(bufferSize), offset(0), isInternalBuffer(true) {
    this->buffer = new unsigned char[bufferSize];
    memset(buffer, 0, bufferSize);
}

BufferWriter::~BufferWriter() {
    if (isInternalBuffer && buffer != nullptr) {
        delete[] buffer;
    }
}

const unsigned char* BufferWriter::getBuffer() {
    return buffer;
}

void BufferWriter::write(const void* data, size_t size) {
    if (check_overflow(size)) {
        throw exception("Buffer overflow");
    }

    memcpy(buffer + offset, data, size);
    offset += size;
}

size_t BufferWriter::getOffset()
{
    return offset;
}

void BufferWriter::write4bytes(uint32_t input) {
    if (check_overflow(4)) {
        throw exception("Buffer is full. Can't append 4 bytes.");
    }
    unsigned int a = input & 0xFF;
    unsigned int b = (input >> 8) & 0xFF;
    unsigned int c = (input >> 16) & 0xFF;
    unsigned int d = (input >> 24) & 0xFF;
    memcpy(buffer + offset, &a, 1);
    memcpy(buffer + offset + 1, &b, 1);
    memcpy(buffer + offset + 2, &c, 1);
    memcpy(buffer + offset + 3, &d, 1);
    offset += 4;
}

void BufferWriter::write2bytes(uint16_t input) {
    if (check_overflow(2)) {
        throw exception("Buffer is full. Can't append 2 bytes.");
    }

    unsigned int a = input & 0xFF;
    unsigned int b = (input >> 8) & 0xFF;
    memcpy(buffer + offset, &a, 1);
    memcpy(buffer + offset + 1, &b, 1);
    offset += 2;
}

void BufferWriter::write1byte(uint8_t input) {
    if (check_overflow(1)) {
        throw exception("Buffer is full. Can't append 1 bytes.");
    }

    unsigned int a = input & 0xFF;
    memcpy(buffer + offset, &a, 1);
    offset += 1;
}

bool BufferWriter::check_overflow(size_t bytesToWrite) {
    if (offset + bytesToWrite > bufferSize) {
        return true;
    }

    return false;
}

void BufferWriter::writeVal(uint8_t val, size_t size) {
    if (check_overflow(size)) {
        string msg = "Buffer is full. Can't append " + size;
        msg += " bytes";
        throw exception(msg.c_str());
    }

    memset(buffer + offset, val, size);
    offset += size;
}


// =================================================================================


BufferReader::BufferReader(const unsigned char* buffer, size_t bufferSize) :
    buffer(buffer), offset(0), bufferSize(bufferSize) {
}

void BufferReader::read(size_t size, void* bufferToWriteTo, size_t bufferToWriteToSize) {
    if (size == 0) {
        return;
    }

    if (size > bufferToWriteToSize) {
        throw exception("Can't read more than buffer size.");
    }

    if (check_overflow(size)) {
        throw exception("Can't read - buffer offset is at the end.");
    }

    memcpy(bufferToWriteTo, buffer + offset, size);
    offset += size;
}

size_t BufferReader::getOffset()
{
    return offset;
}

uint32_t BufferReader::read4bytes() {
    if (check_overflow(4)) {
        throw exception("Buffer is full. Can't read 4 bytes.");
    }
    uint32_t x = *(uint32_t*)(buffer + offset);
    offset += 4;
    return x;
}

uint16_t BufferReader::read2bytes() {
    if (check_overflow(2)) {
        throw exception("Buffer is full. Can't read 2 bytes.");
    }

    uint16_t x = *(uint16_t*)(buffer + offset);
    offset += 2;
    return x;
}

uint8_t BufferReader::read1byte() {
    if (check_overflow(1)) {
        throw exception("Buffer is full. Can't read 1 bytes.");
    }

    uint8_t x = *(uint8_t*)(buffer + offset);
    offset += 1;
    return x;
}

bool BufferReader::check_overflow(size_t bytesToRead) {
    if (offset + bytesToRead > bufferSize) {
        return true;
    }

    return false;
}

void BufferReader::addOffset(size_t amount) {
    if (amount + offset > bufferSize) {
        throw exception("Can't add offset: amount with offset will overflow buffer size.");
    }

    offset += amount;
}