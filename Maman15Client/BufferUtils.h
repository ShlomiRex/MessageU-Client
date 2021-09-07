#pragma once
#include <cstdint>
#include <cstring>
#include <exception>
#include <string>

//Little endian buffer writer
class BufferWriter
{
private:
	char* buffer;
	size_t bufferSize;

	size_t offset;

	bool check_overflow(size_t bytesGoingToWrite);

public:
	BufferWriter(char* buffer, size_t bufferSize);

	void write1byte(uint8_t);
	void write2bytes(uint16_t);
	void write4bytes(uint32_t);

	void write(const void* data, size_t size);
	void writeVal(uint8_t val, size_t size);
	size_t getOffset();
};

class BufferReader
{
private:
	const char* buffer;
	size_t bufferSize;

	size_t offset;

	bool check_overflow(size_t bytesGoingToRead);

public:
	BufferReader(const char* buffer, size_t bufferSize);

	uint8_t read1byte();
	uint16_t read2bytes();
	uint32_t read4bytes();

	void read(size_t size, void* bufferToWriteTo, size_t bufferToWriteToSize);
	size_t getOffset();
};