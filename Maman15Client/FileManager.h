#pragma once

#include "ProtocolDefenitions.h"
#include <string>
#include <iostream>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/algorithm/hex.hpp>

class FileManager
{
public:
	static void getSavedClientId(ClientId buffer);
	std::string getSavedUsername();
	const char* getSavedPrivateKey();
};

