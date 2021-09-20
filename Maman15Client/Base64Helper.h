#pragma once

#include <string>

class Base64Helper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};

