﻿#include "Client.h"
#include <boost/filesystem/operations.hpp>
#include "Debug.h"
#include "AsymmetricCrypto.h"
#include "ProtocolDefenitions.h"
#include "Menu.h"
#include "MessageU_User.h"
#include "MessageU.h"

#define DEBUG_PREFIX "[main] "

using namespace std;
using namespace MessageUProtocol;

int rsa_example()
{
	// plain text (could be binary data as well)
	string plain = "Super Secret!";
	cout << "plain:" << endl;
	hexify((const unsigned char*)plain.c_str(), plain.size());		// print binary data nicely

	// 1. Create an RSA decryptor. this is done here to generate a new private/public key pair
	RSAPrivateWrapper client1_private_rsa_wrapper;

	// 2. get the public key
	string pubkey = client1_private_rsa_wrapper.getPublicKey();	// you can get it as string ...

	// 3. create an RSA encryptor
	RSAPublicWrapper rsapub(pubkey);
	string cipher = rsapub.encrypt((const char*)plain.c_str(), plain.size());	// you can encrypt a const char* or an string
	cout << "cipher:" << endl;
	hexify((unsigned char*)cipher.c_str(), cipher.length());	// print binary data nicely


	// 4. get the private key and encode it as base64 (base64 in not necessary for an RSA decryptor.)
	auto privatekey = client1_private_rsa_wrapper.getPrivateKey();
	string base64key = Base64Wrapper::encode(privatekey);

	// 5. create another RSA decryptor using an existing private key (decode the base64 key to an string first)
	RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(base64key));

	string decrypted = rsapriv_other.decrypt(cipher);		// 6. you can decrypt an string or a const char* buffer
	cout << "decrypted:" << endl;
	hexify((unsigned char*)decrypted.c_str(), decrypted.length());	// print binary data nicely

	return 0;
}

void foo() {
	//Generate keys
	PublicKey pubkey_generated = { 0 };
	PrivateKey privkey_generated = { 0 };
	string pubkey_generated_str, privkey_generated_str;
	{
		string pubkey_str, privkey_str;
		AsymmetricCrypto::generateKeys(pubkey_str, privkey_str);

		if (pubkey_str.size() != S_PUBLIC_KEY) {
			throw "ERROR KEY LEN";
		}
		memcpy(pubkey_generated, pubkey_str.c_str(), S_PUBLIC_KEY);

		//TODO: privkey_str size is 633! NOT 160!
		//memcpy(privkey_generated, privkey_str.c_str(), S_PRIVATE_KEY);

		pubkey_generated_str = pubkey_str;
		privkey_generated_str = privkey_str;
	}

	{
		string plain = "Hello!";
		string cipher = AsymmetricCrypto::encrypt(plain, pubkey_generated);
		string decrypted = AsymmetricCrypto::decrypt(cipher, privkey_generated_str);

		LOG("TEST");
	}

	{
		//Encode, write to file
		{
			size_t boost_base64_encode_size_needed = boost::beast::detail::base64::encoded_size(privkey_generated_str.size());
			char* boost_base64_encode_buffer = new char[boost_base64_encode_size_needed];
			size_t encoded_buffer_size = boost::beast::detail::base64::encode(boost_base64_encode_buffer, privkey_generated_str.c_str(), privkey_generated_str.size());
			ofstream file("test.txt");
			file.write(boost_base64_encode_buffer, encoded_buffer_size);
			file.close();

			LOG("TEST");
		}

		//Decode, read from file, retreive private key
		{
			string line;
			ifstream file2("test.txt");
			getline(file2, line);
			file2.close();

			size_t base64_decode_size_needed = boost::beast::detail::base64::decoded_size(privkey_generated_str.size());
			char* base64_decode_buffer = new char[base64_decode_size_needed];
			auto abc = boost::beast::detail::base64::decode(base64_decode_buffer, privkey_generated_str.c_str(), privkey_generated_str.size());

			LOG("TEST");
		}
	}
}

void RSA_BASE64_TEST() {
	const char* file_name = "test.txt";
	RSAPrivateWrapper rsaPrivWrapper;
	string privkey = rsaPrivWrapper.getPrivateKey();
	string pubkey = rsaPrivWrapper.getPublicKey();
	//Write base64 to file
	{
		ofstream file(file_name);
		string base64 = Base64Wrapper::encode(privkey);
		file.write(base64.c_str(), base64.size());
		file.close();
	}
	//Read base64 from file
	string decoded_privkey;
	{
		ifstream file(file_name);

		char buffer[2048] = { 0 };
		file.read(buffer, 2048);
		string privkey_str(buffer);

		decoded_privkey = Base64Wrapper::decode(privkey_str);
	}
	//Check if the decoded private key is diffirent
	{
		int i1 = privkey.size();
		int i2 = decoded_privkey.size();
		assert(i1 == i2);

		for (size_t i = 0; i < i1; i++) {
			char c1 = privkey.at(i);
			char c2 = decoded_privkey.at(i);
			assert(c1 == c2);
		}
	}

	{
		RSAPublicWrapper rsapub(pubkey);
		string plain = "Top Secret";
		string cipher = rsapub.encrypt(plain);

		{
			RSAPrivateWrapper rsaPrivWrapper2(decoded_privkey);
			string plain_decrypted = rsaPrivWrapper2.decrypt(cipher);

			assert(plain.compare(plain_decrypted) == 0);
		}
	}

	{
		RSAPrivateWrapper client2_rsaPrivWrapper;
		string client2_privkey = client2_rsaPrivWrapper.getPrivateKey();
		string client2_pubkey = client2_rsaPrivWrapper.getPublicKey();

		//Encrypt something for client 1
		RSAPublicWrapper rsapub(pubkey);
		string client2_plain = "Hello World!";
		string cipher = rsapub.encrypt(client2_plain);

		//Client 1 decrypt
		RSAPrivateWrapper client1_rsapriv(privkey);
		string client1_plain = client1_rsapriv.decrypt(cipher);

		assert(client2_plain.compare(client1_plain) == 0);
	}
	std::remove(file_name);
}

int main()
{
	RSA_BASE64_TEST();
	
	string ip, port;
	FileManager::readServer(ip, port);

	MessageU messageU(ip, port);
	messageU.start(); //loops
	LOG("Finished running, exiting program");
}










/*



int aes_example()
{
	cout << endl << endl << "----- AES EXAMPLE -----" << endl << endl;

	string plaintext = "Once upon a time, a plain text dreamed to become a cipher";
	cout << "Plain:" << endl << plaintext << endl;

	// 1. Generate a key and initialize an AESWrapper. You can also create AESWrapper with default constructor which will automatically generates a random key.
	unsigned char key[AESWrapper::DEFAULT_KEYLENGTH];
	AESWrapper aes(AESWrapper::GenerateKey(key, AESWrapper::DEFAULT_KEYLENGTH), AESWrapper::DEFAULT_KEYLENGTH);

	// 2. encrypt a message (plain text)
	string ciphertext = aes.encrypt(plaintext.c_str(), plaintext.length());
	cout << "Cipher:" << endl;
	hexify(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length());	// print binary data nicely

	// 3. decrypt a message (cipher text)
	string decrypttext = aes.decrypt(ciphertext.c_str(), ciphertext.length());
	cout << "Decrypted:" << endl << decrypttext << endl;

	return 0;
}
*/

/*
int rsa_example()
{
	cout << endl << endl << "----- RSA EXAMPLE -----" << endl << endl;

	// plain text (could be binary data as well)
	unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	cout << "plain:" << endl;
	hexify(plain, sizeof(plain));		// print binary data nicely

	// 1. Create an RSA decryptor. this is done here to generate a new private/public key pair
	RSAPrivateWrapper client1_private_rsa_wrapper;

	// 2. get the public key
	string pubkey = client1_private_rsa_wrapper.getPublicKey();	// you can get it as string ...

	char pubkeybuff[RSAPublicWrapper::KEYSIZE];
	client1_private_rsa_wrapper.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);	// ...or as a char* buffer

	// 3. create an RSA encryptor
	RSAPublicWrapper rsapub(pubkey);
	string cipher = rsapub.encrypt((const char*)plain, sizeof(plain));	// you can encrypt a const char* or an string
	cout << "cipher:" << endl;
	hexify((unsigned char*)cipher.c_str(), cipher.length());	// print binary data nicely


	// 4. get the private key and encode it as base64 (base64 in not necessary for an RSA decryptor.)
	string base64key = Base64Wrapper::encode(client1_private_rsa_wrapper.getPrivateKey());

	// 5. create another RSA decryptor using an existing private key (decode the base64 key to an string first)
	RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(base64key));

	string decrypted = rsapriv_other.decrypt(cipher);		// 6. you can decrypt an string or a const char* buffer
	cout << "decrypted:" << endl;
	hexify((unsigned char*)decrypted.c_str(), decrypted.length());	// print binary data nicely

	return 0;
}
*/