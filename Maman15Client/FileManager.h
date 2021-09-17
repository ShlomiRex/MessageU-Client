#pragma once

#include "ProtocolDefenitions.h"
#include <string>
#include <iostream>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/algorithm/hex.hpp>
#include "Debug.h"

class FileManager
{
public:
	static void getSavedClientId(ClientId buffer);
	static std::string getSavedUsername();
	static const char* getSavedPrivateKey();
};

