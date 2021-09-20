#pragma once

#include <immintrin.h>	// _rdrand32_step

#include "ProtocolDefenitions.h"

//using namespace MessageUProtocol; 

typedef struct {
	MessageUProtocol::User user;
	MessageUProtocol::SymmetricKey symKey;
} SecureChannel;

class SymmetricCrypto
{
public:
	static void generateKey(MessageUProtocol::SymmetricKey& result_symkey);
};

