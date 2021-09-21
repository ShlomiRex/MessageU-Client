#pragma once
#include <iomanip>
#include <iostream>
#include <sstream>

void hexify(const unsigned char* buffer, unsigned int length);
std::string hexify_str(const char* buffer, size_t bufferSize);

bool is_number(const std::string& s);

bool is_zero_filled(const char* arr, size_t s_arr);

//Compare 2 simillar size buffers (can have zero / null terminator, will check all characters)
bool buffer_compare(const char* buff1, const char* buff2, size_t s_buffers);