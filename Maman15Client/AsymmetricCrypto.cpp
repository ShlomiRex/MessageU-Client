#include "AsymmetricCrypto.h"

#define DEBUG_PREFIX "[AsymCrypto] "

using namespace std;
using namespace CryptoPP;

void AsymmetricCrypto::generateKeys(string& result_pubkey, string& result_privkey) {
	DEBUG("Generating asymmetric key pairs...");

	//After we generate, we don't care about the seed. It's fine to discard from memory.
	AutoSeededRandomPool rng;

	//Generate keys
	RSA::PrivateKey privatekey;
	privatekey.GenerateRandomWithKeySize(rng, S_ASYMMETRIC_KEY * 8); //convert bytes to bits
	RSA::PublicKey publickey(privatekey);
	
	//Save keys
	StringSink pubSink(result_pubkey);
	StringSink priSink(result_privkey);

	//Encode seperatly for later use
	publickey.DEREncode(pubSink);
	privatekey.DEREncode(priSink);

	if (result_pubkey.size() != S_PUBLIC_KEY) {
		throw PublicKeyLengthError(S_PUBLIC_KEY, result_pubkey.size());
	}

	DEBUG("Public key size: " << result_pubkey.size());
	DEBUG("Private key size: " << result_privkey.size());
}

string AsymmetricCrypto::encrypt(const string& text, const MessageUProtocol::PublicKey& publickey) {
	AutoSeededRandomPool rng;

	//Decode public key
	RSA::PublicKey decoded_pubkey;

	//Cast PublicKey to string
	string publickey_str(publickey, S_PUBLIC_KEY);
	//Read from the casted string and decode pub key
	StringSource ss(publickey_str, true);
	decoded_pubkey.BERDecode(ss);

	//RSA::PublicKey pubkey2;
	//StringSource ss(publickey, true);
	//pubkey2.Load(ss);

	//Save again
	//string pubkey_save;
	//StringSink sink1000(pubkey_save);
	//pubkey2.Save(sink1000);

	//LOG("Public key size: " << pubkey_save.size());
	//hexify((const unsigned char*)pubkey_save.c_str(), pubkey_save.size());

	//Encrypt message

	string cipher;
	auto x = new StringSink(cipher);
	RSAES_OAEP_SHA_Encryptor e(decoded_pubkey);
	auto pk_encfilter = new PK_EncryptorFilter (rng, e, x);
	StringSource ss2(text, true, pk_encfilter); //attachment is RSA filter


	//I tried moving old code to stack, because I saw 'new' in StringSource and PK_EncryptorFilter.
	//What I learned from the documentation:
	//Basically, deconstructor of StringSource deconstructs both attachment (pk_encfilter) and string sink.
	//So I got memory errors and I didn't understand why. That's why.
	//So this way is good, no memory leaks.

	return cipher;
}

string AsymmetricCrypto::decrypt(const string& cipher, const string& privkey)
{
	AutoSeededRandomPool rng;
	string decrypted;

	RSA::PrivateKey privatekey;

	//Decode from original string
	StringSource ss(privkey, true);
	privatekey.BERDecode(ss);

	//Decrypt cipher
	RSAES_OAEP_SHA_Decryptor d(privatekey);
	auto x = new StringSink(decrypted);
	auto pk_decfilter = new PK_DecryptorFilter(rng, d, x);
	StringSource ss_cipher(cipher, true, pk_decfilter);

	//Same as in encrypt. StringSource calls deconstructors of StringSink and attachment.

	return decrypted;
}
