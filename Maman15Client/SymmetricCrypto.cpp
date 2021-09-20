#include "SymmetricCrypto.h"

#define DEBUG_PREFIX "[SymCrypto] "

using namespace MessageUProtocol;

void SymmetricCrypto::generateKey(SymmetricKey& result_symkey)
{
	for (size_t i = 0; i < S_SYMMETRIC_KEY; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&result_symkey[i]));
	
}
