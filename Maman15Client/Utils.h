#pragma once
#include <iomanip>
#include <iostream>
#include <sstream>

void hexify(const unsigned char* buffer, unsigned int length);
std::string hexify_str(const char* buffer, size_t bufferSize);