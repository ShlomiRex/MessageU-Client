#pragma once
#include <iomanip>
#include <iostream>
#include <sstream>
#include "ProtocolDefenitions.h"

void hexify(const unsigned char* buffer, unsigned int length);
std::string hexify_str(const unsigned char* buffer, size_t bufferSize);

bool is_number(const std::string& s);

bool is_zero_filled(const unsigned char* arr, size_t s_arr);

//Compare 2 simillar size buffers (can have zero / null terminator, will check all characters)
bool buffer_compare(const unsigned char* buff1, const unsigned char* buff2, size_t s_buffers);

void str_to_pubKey(const std::string& str, MessageUProtocol::PublicKey& result);
void str_to_symmKey(const std::string& str, MessageUProtocol::SymmetricKey& result);