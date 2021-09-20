#include "Client.h"
#include "InteractiveMenu.h"
#include <boost/filesystem/operations.hpp>
#include "MenuDefenitions.h"
#include "Debug.h"
#include "AsymmetricCrypto.h"
#include "ProtocolDefenitions.h"

//TEST

#include <files.h>
#include <modes.h>
#include <osrng.h>
#include <rsa.h>
#include <sha.h>
#include <hex.h>
#include <base64.h>
#include "RSAWrapper.h"
//TEST

#define DEBUG_PREFIX "[main] "

//TODO: When implimented send file, client version is 2!
//TODO: Else, when send file is not implimented, client version is 1!
#define CLIENT_VERSION 1

using namespace std;
using namespace MessageUProtocol;

string encrypt2(string pubkey) {
	unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	cout << "plain:" << endl;
	hexify(plain, sizeof(plain));		// print binary data nicely

	RSAPublicWrapper rsapub(pubkey);
	string cipher = rsapub.encrypt((const char*)plain, sizeof(plain));	// you can encrypt a const char* or an string
	cout << "cipher:" << endl;
	hexify((unsigned char*)cipher.c_str(), cipher.length());	// print binary data nicely

	return cipher;
}

void getKeys2(string& pub, string& priv) {
	// 1. Create an RSA decryptor. this is done here to generate a new private/public key pair
	RSAPrivateWrapper client1_private_rsa_wrapper;

	// 2. get the public key
	string pubkey = client1_private_rsa_wrapper.getPublicKey();	// you can get it as string ...

	pub = pubkey;


	string _priv = client1_private_rsa_wrapper.getPrivateKey();
	priv = _priv;
}

string decrypt2(string privkey, string cipher) {
	RSAPrivateWrapper rsapriv_other(privkey);

	string decrypted = rsapriv_other.decrypt(cipher);		// 6. you can decrypt an string or a const char* buffer
	cout << "decrypted:" << endl;
	hexify((unsigned char*)decrypted.c_str(), decrypted.length());	// print binary data nicely

	return decrypted;
}

int rsa_example()
{
	/*
	cout << endl << endl << "----- RSA EXAMPLE -----" << endl << endl;

	// plain text (could be binary data as well)
	unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	cout << "plain:" << endl;
	hexify(plain, sizeof(plain));		// print binary data nicely
	*/
	
	/*
	// 1. Create an RSA decryptor. this is done here to generate a new private/public key pair
	RSAPrivateWrapper client1_private_rsa_wrapper;

	// 2. get the public key
	string pubkey = client1_private_rsa_wrapper.getPublicKey();	// you can get it as string ...

	char pubkeybuff[RSAPublicWrapper::KEYSIZE];
	client1_private_rsa_wrapper.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);	// ...or as a char* buffer
	*/

	/*
	string pubkey, privatekey;
	getKeys(pubkey, privatekey);

	string cipher = encrypt(pubkey);

	string decrypted = decrypt(privatekey, cipher);
	*/
	LOG("TEST");
	/*
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
	*/
	return 0;
}



int main()
{
	//AsymmetricCrypto::test();
	//rsa_example();

	
	string pubkey, privkey;
	AsymmetricCrypto::generateKeys(pubkey, privkey);
	PublicKey pub100;
	memcpy(pub100, pubkey.c_str(), S_PUBLIC_KEY);

	string cipher = AsymmetricCrypto::encrypt("Hello!", pub100);
	string decrypted = AsymmetricCrypto::decrypt(cipher, privkey);
	

	DEBUG("Reading from " << FILE_SERVER);
	ifstream server_info(FILE_SERVER);
	char buff[S_FILE_SERVER] = { 0 };
	server_info.read(buff, S_FILE_SERVER);
	string str_buff = buff;
	size_t index = str_buff.find(':');

	string ip = str_buff.substr(0, index);
	string port = str_buff.substr(index + 1);

	if (ip.size() == 0 && port.size() == 0) {
		LOG("ERROR: IP or port is empty. Check " << FILE_SERVER);
		return -1;
	}

	DEBUG("IP: " << ip);
	DEBUG("Port: " << port);

	//Interactive menu sets these variables. Saved for other choices to use. 

	//My 'me.info' stuff
	ClientId myClientId = { 0 };
	string myUsername = "";

	try {
		FileManager::getSavedClientId(myClientId);
		myUsername = FileManager::getSavedUsername(); //Username helps identify (for debugging and also its nice) who I am, what username I currently use.
	}
	catch (InfoFileNotExistException) {
		//do nothing
	}

	//Saved users is set when client requests get clients from server.
	vector<User> savedUsers;
	//Saved public key for later use
	PublicKey savedPubKey = { 0 };
	bool pubKeySaved = false;

	//And lastly, generated symmetric key, when we want to send symmetric key.
	vector<SecureChannel> secureChannels;

	while (true) {
		InteractiveMenu::show_menu(myUsername, &myClientId);

		Menu::ClientChoices choice = InteractiveMenu::get_choice();

		try {
			Client client(ip, port, CLIENT_VERSION);

			if (choice == Menu::ClientChoices::registerUser) {
				myUsername = InteractiveMenu::readUsername();
				client.connect();
				client.registerUser(myUsername, myClientId);
			}
			else if (choice == Menu::ClientChoices::reqClientList) {
				client.connect();
				client.getClients(&savedUsers);
			}
			else if (choice == Menu::ClientChoices::reqPublicKey) {
				InteractiveMenu::getClientId(myClientId, &savedUsers);
				client.connect();
				client.getPublicKey(myClientId, savedPubKey);
				pubKeySaved = true;
			}
			else if (choice == Menu::ClientChoices::sendMessage) {
				//TODO: Impliment
				LOG("Not yet implimented");
			}
			else if (choice == Menu::ClientChoices::sendReqSymmetricKey) {
				FileManager::getSavedClientId(myClientId);
					
				ClientId dest_clientId;
				InteractiveMenu::getClientId(dest_clientId, &savedUsers);
				client.connect();
				client.getSymKey(myClientId, dest_clientId);
			}
			else if (choice == Menu::ClientChoices::sendFile) {
				//TODO: Impliment as bonous
				LOG("Not yet implimented");
			}
			else if (choice == Menu::ClientChoices::reqPullWaitingMessages) {
				FileManager::getSavedClientId(myClientId);

				client.connect();
				client.pullMessages(myClientId, savedUsers);
			}
			else if (choice == Menu::ClientChoices::sendSymmetricKey) {
				//Get dest client
				ClientId dest_clientId;
				InteractiveMenu::getClientId(dest_clientId, &savedUsers);

				//Get destination client public key
				if (pubKeySaved) {

					/*
					SecureChannel sec;
					memcpy(sec.user.client_id, dest_clientId, S_CLIENT_ID);

					for (const auto& x : savedUsers) {
						if (strncmp(x.client_id, dest_clientId, S_CLIENT_ID) == 0) {
							strncpy_s(sec.user.username, x.username, S_USERNAME);
							break;
						}
					}
					*/

					//Generate new symmetric key
					SymmetricKey symkey;
					SymmetricCrypto::generateKey(symkey);

					//Create 
					//SecureChannel sec;
					//memcpy(sec.user.client_id, dest_clientId, S_CLIENT_ID);


					client.connect();
					client.sendSymKey(myClientId, symkey, dest_clientId, savedPubKey);
				}
				else {
					LOG("You must first get public key.");
				}
			}
			else if (choice == Menu::ClientChoices::exitProgram) {
				break;
			}
			else {
				LOG("ERROR: Unknown client choice: " << static_cast<int>(choice));
			}
		}
		catch (exception& e) {
			LOG(e.what());
		}
		cout << "\n\n\n";
	}

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