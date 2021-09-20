#pragma once
#include <iomanip>
#include <iostream>
#include <sstream>

void hexify(const unsigned char* buffer, unsigned int length);
std::string hexify_str(const char* buffer, size_t bufferSize);

bool is_number(const std::string& s);

bool is_zero_filled(const char* arr, size_t s_arr);