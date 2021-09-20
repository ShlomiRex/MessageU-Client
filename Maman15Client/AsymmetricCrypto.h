#pragma once

//std
#include <string>

//CryptoPP
#include <rsa.h>
#include <osrng.h>
#include <files.h>

//Project
#include "ProtocolDefenitions.h"
#include "Debug.h"
#include "Utils.h"
#include "RSAWrapper.h"

class AsymmetricCrypto
{
public:
	static void generateKeys(std::string& pubkey, std::string& privkey);
	static std::string encrypt(const std::string& text, const MessageUProtocol::PublicKey& pubkey);
	static std::string decrypt(const std::string& cipher, const std::string& privkey);
};

struct PublicKeyLengthError : public std::exception {
private:
	size_t expected, got;
	std::string mystr;
public:
	PublicKeyLengthError(size_t expected, size_t got) : expected(expected), got(got) {
		mystr = "Public key length should be: " + expected;
		mystr += ", instead the size is: " + got;
	}

	const char* what() const throw() {
		return mystr.c_str();
	}
};

/*
Example:

	string pubkey, privkey;
	AsymmetricCrypto::generateKeys(pubkey, privkey);
	string cipher = AsymmetricCrypto::encrypt("Hello!", pubkey);
	string decrypted = AsymmetricCrypto::decrypt(cipher, privkey);

*/