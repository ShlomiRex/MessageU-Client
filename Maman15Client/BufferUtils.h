#pragma once
#include <cstdint>
#include <cstring>
#include <exception>
#include <string>
#include <stdexcept>


//Little endian buffer writer
class BufferWriter
{
private:
	unsigned char* buffer;
	size_t bufferSize;

	size_t offset;

	bool check_overflow(size_t bytesGoingToWrite) const;

    //If this class creates heap allocated buffer, we set this to true.
    //Else, we set this to false.
    //This indicates who owns the buffer, so we can safely free the heap.
	bool isInternalBuffer;
public:
	BufferWriter(size_t bufferSize); //Create new buffer, and remember to delete at the deconstructor!
	BufferWriter(unsigned char* buffer, size_t bufferSize);
	~BufferWriter();

	void write1byte(uint8_t);
	void write2bytes(uint16_t);
	void write4bytes(uint32_t);

	void write(const void* data, size_t size);
	void writeVal(uint8_t val, size_t size);
	size_t getOffset() const;
	const unsigned char* getBuffer();
};

class BufferReader
{
private:
	const unsigned char* buffer;
	size_t bufferSize;

	size_t offset;

	bool check_overflow(size_t bytesGoingToRead) const;

public:
	BufferReader(const unsigned char* buffer, size_t bufferSize);

	//To skip some bytes, you can add to offset.
	void addOffset(size_t amount);

	uint8_t read1byte();
	uint16_t read2bytes();
	uint32_t read4bytes();

	void read(size_t size, void* bufferToWriteTo, size_t bufferToWriteToSize);
	size_t getOffset() const;
};