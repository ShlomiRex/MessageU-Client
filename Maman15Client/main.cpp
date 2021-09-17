#include "Client.h"
#include "InteractiveMenu.h"
#include <boost/filesystem/operations.hpp>
#include "MenuDefenitions.h"
#include "Debug.h"

#define DEBUG_PREFIX "[main] "

using namespace std;

int main()
{
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
	ClientId myClientId;
	FileManager::getSavedClientId(myClientId);
	string myUsername = FileManager::getSavedUsername(); //Username helps identify (for debugging and also its nice) who I am, what username I currently use.

	//Saved users is set when client requests get clients from server.
	vector<User> savedUsers;

	while (true) {
		InteractiveMenu::show_menu(myUsername);
		Menu::ClientChoices choice = InteractiveMenu::get_choice();

		//If using database, client version is 2!
		bool isUsingSQLDatabase = true; // TODO: Change?
		try {
			Client client(ip, port, 1);

			if (choice == Menu::ClientChoices::registerUser) {
				myUsername = InteractiveMenu::readUsername();
				client.connect();
				client.registerUser(myUsername);
			}
			else if (choice == Menu::ClientChoices::reqClientList) {
				client.connect();
				client.getClients(&savedUsers);
			}
			else if (choice == Menu::ClientChoices::reqPublicKey) {
				try {
					InteractiveMenu::getClientId(myClientId, &savedUsers);
					client.connect();
					client.getPublicKey(myClientId);
				}
				catch (EmptyClientsList) {
					LOG("You must first get clients list from server.");
				}
			}
			else if (choice == Menu::ClientChoices::sendText) {
				LOG("Not yet implimented");
				/*
				string username = InteractiveMenu::readUsername();
				string text = InteractiveMenu::readText();

				client.sendText(username, text);
				*/
			}
			else if (choice == Menu::ClientChoices::sendReqSymmetricKey) {
				try {
					FileManager::getSavedClientId(myClientId);

					InteractiveMenu::getClientId(myClientId, &savedUsers);
					client.connect();
					client.getSymKey(myClientId, myClientId);
				}
				catch (EmptyClientsList) {
					LOG("You must first get clients list from server.");
				}
			}
			else if (choice == Menu::ClientChoices::sendFile) {
				//TODO: Impliment as bonous
			}
			else if (choice == Menu::ClientChoices::reqPullWaitingMessages) {
				if (savedUsers.size() == 0) {
					LOG("You must first get clients list from server (in order to map usernames to client id's.");
				}
				else {
					FileManager::getSavedClientId(myClientId);

					client.connect();
					client.pullMessages(myClientId, savedUsers);
				}
			}
			else if (choice == Menu::ClientChoices::sendSymmetricKey) {
				//TODO: Impliment

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


#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <iostream>
#include <iomanip>

void hexify(const unsigned char* buffer, unsigned int length)
{
	std::ios::fmtflags f(std::cout.flags());
	std::cout << std::hex;
	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	std::cout << std::endl;
	std::cout.flags(f);
}


int aes_example()
{
	std::cout << std::endl << std::endl << "----- AES EXAMPLE -----" << std::endl << std::endl;

	std::string plaintext = "Once upon a time, a plain text dreamed to become a cipher";
	std::cout << "Plain:" << std::endl << plaintext << std::endl;

	// 1. Generate a key and initialize an AESWrapper. You can also create AESWrapper with default constructor which will automatically generates a random key.
	unsigned char key[AESWrapper::DEFAULT_KEYLENGTH];
	AESWrapper aes(AESWrapper::GenerateKey(key, AESWrapper::DEFAULT_KEYLENGTH), AESWrapper::DEFAULT_KEYLENGTH);

	// 2. encrypt a message (plain text)
	std::string ciphertext = aes.encrypt(plaintext.c_str(), plaintext.length());
	std::cout << "Cipher:" << std::endl;
	hexify(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length());	// print binary data nicely

	// 3. decrypt a message (cipher text)
	std::string decrypttext = aes.decrypt(ciphertext.c_str(), ciphertext.length());
	std::cout << "Decrypted:" << std::endl << decrypttext << std::endl;

	return 0;
}


int rsa_example()
{
	std::cout << std::endl << std::endl << "----- RSA EXAMPLE -----" << std::endl << std::endl;

	// plain text (could be binary data as well)
	unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	std::cout << "plain:" << std::endl;
	hexify(plain, sizeof(plain));		// print binary data nicely

	// 1. Create an RSA decryptor. this is done here to generate a new private/public key pair
	RSAPrivateWrapper rsapriv;

	// 2. get the public key
	std::string pubkey = rsapriv.getPublicKey();	// you can get it as std::string ...

	char pubkeybuff[RSAPublicWrapper::KEYSIZE];
	rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);	// ...or as a char* buffer

	// 3. create an RSA encryptor
	RSAPublicWrapper rsapub(pubkey);
	std::string cipher = rsapub.encrypt((const char*)plain, sizeof(plain));	// you can encrypt a const char* or an std::string
	std::cout << "cipher:" << std::endl;
	hexify((unsigned char*)cipher.c_str(), cipher.length());	// print binary data nicely


	// 4. get the private key and encode it as base64 (base64 in not necessary for an RSA decryptor.)
	std::string base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());

	// 5. create another RSA decryptor using an existing private key (decode the base64 key to an std::string first)
	RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(base64key));

	std::string decrypted = rsapriv_other.decrypt(cipher);		// 6. you can decrypt an std::string or a const char* buffer
	std::cout << "decrypted:" << std::endl;
	hexify((unsigned char*)decrypted.c_str(), decrypted.length());	// print binary data nicely

	return 0;
}



int main()
{
	aes_example();

	rsa_example();

	return 0;
}



*/