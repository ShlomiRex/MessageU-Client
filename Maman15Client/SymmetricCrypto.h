#pragma once

#include <immintrin.h>	// _rdrand32_step

#include "ProtocolDefenitions.h"

//using namespace MessageUProtocol; 

class SymmetricCrypto
{
public:
	static void generateKey(MessageUProtocol::SymmetricKey& result_symkey);
};

