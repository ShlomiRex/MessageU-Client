#pragma once

#include "ProtocolDefenitions.h"
#include <string>
#include <iostream>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/algorithm/hex.hpp>
#include "Debug.h"

//using namespace std;
//using namespace MessageUProtocol;

class FileManager
{
public:
	static void getSavedClientId(MessageUProtocol::ClientId buffer);
	static std::string getSavedUsername();
	static const char* getSavedPrivateKey();
};

struct InfoFileNotExistException : public std::exception {
private:
	std::string mystr;
public:
	InfoFileNotExistException() {
		mystr += FILE_REGISTER;
		mystr += " doesn't exist.";
	}
	const char* what() const noexcept {
		return mystr.c_str();
	}
};
