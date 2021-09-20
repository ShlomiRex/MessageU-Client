﻿#include "Client.h"
//#include "InteractiveMenu.h" //TODO: Remove
#include <boost/filesystem/operations.hpp>
#include "Debug.h"
#include "AsymmetricCrypto.h"
#include "ProtocolDefenitions.h"
#include "Menu.h"

//TEST
/*
#include <files.h>
#include <modes.h>
#include <osrng.h>
#include <rsa.h>
#include <sha.h>
#include <hex.h>
#include <base64.h>
#include "RSAWrapper.h"
*/
//TEST

#define DEBUG_PREFIX "[main] "

//TODO: When implimented send file, client version is 2!
//TODO: Else, when send file is not implimented, client version is 1!
#define CLIENT_VERSION 1

using namespace std;
using namespace MessageUProtocol;

void updateUsers(Menu& menuobj, vector<MenuUser>* serverResponse) {
	//Clear current users from memory
	menuobj.users.clear();
	//Save new users
	menuobj.users.assign(serverResponse->begin(), serverResponse->end());
}

//We re-use this code twice: explicitly (by user input) or by asking him if he wants to fetch it automatically.
void registerMyself(Menu& menu, Client& client) {
	//Temporary store users from the server response
	vector<MenuUser> menuUsers;

	//Get users from server
	vector<MessageUProtocol::User> users;

	client.connect();
	ClientId myClientId;
	menu.getMyClientId(myClientId);
	client.getClients(myClientId, &users);

	for (const auto& x : users) {
		//It's ok, vector does the copy operator, so it won't be freed after loop,
		MenuUser menuUser;
		memcpy(menuUser.client_id, x.client_id, S_CLIENT_ID);
		memset(menuUser.publicKey, 0, S_PUBLIC_KEY); //Here, we still don't know the public ip of each client. But it's ok, we cna deal with it later.
		memcpy(menuUser.username, x.username, S_USERNAME);

		menuUsers.push_back(menuUser);
	}

	if (menuUsers.size() > 0) {
		//Update our saved users in memory
		updateUsers(menu, &menuUsers);

		LOG("Users saved in memory for later use.");
	}
}

void aquirePublicKey(Menu& menu, Client& client) {
	menu.showUsers();

	MenuUser destUser = menu.chooseUser();

	client.connect();

	ClientId myClientId;
	menu.getMyClientId(myClientId);
	//Update 'destUser' with new public key
	client.getPublicKey(myClientId, destUser.client_id, destUser.publicKey);

	//Get that public key and update menu users
	menu.setUserPublicKey(destUser.client_id, destUser.publicKey);
}

int main()
{
	//AsymmetricCrypto::test();
	//rsa_example();

	
	/*
	string pubkey, privkey;
	AsymmetricCrypto::generateKeys(pubkey, privkey);
	PublicKey pub100;
	memcpy(pub100, pubkey.c_str(), S_PUBLIC_KEY);

	string cipher = AsymmetricCrypto::encrypt("Hello!", pub100);
	string decrypted = AsymmetricCrypto::decrypt(cipher, privkey);
	*/

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

	Menu menu;

	try {
		//Read me.info and set my username, clientid
		string myUsername = "";
		ClientId myClientId = { 0 };

		FileManager::getSavedClientId(myClientId);
		myUsername = FileManager::getSavedUsername(); //Username helps identify (for debugging and also its nice) who I am, what username I currently use.

		menu.setUsername(myUsername);
		menu.setClientId(myClientId);

		menu.setRegistered();
	}
	catch (InfoFileNotExistException) {
		//do nothing
	}

	//And lastly, generated symmetric key, when we want to send symmetric key.
	//vector<SecureChannel> secureChannels;


	while (true) {
		menu.show();
		ClientChoices choice = menu.get_choice();

		//Create client for the request.
		Client client(ip, port, CLIENT_VERSION);

		//Read my own info
		string myUsername = menu.getUsername();
		ClientId myClientId;
		menu.getMyClientId(myClientId);

		try {
			if (choice == ClientChoices::registerUser) {
				if (myUsername.size() == 0) {
					menu.readAndSetMyUsername();

					client.connect();
					myUsername = menu.getUsername();
					client.registerUser(myUsername, myClientId);

					menu.setRegistered();
				}
				else {
					LOG("'" << myUsername << "', your already registered!");
				}
			}
			else if (choice == ClientChoices::reqClientList) {
				registerMyself(menu, client);
			}
			else if (choice == ClientChoices::reqPublicKey) {
				aquirePublicKey(menu, client);
			}
			else if (choice == ClientChoices::sendMessage) {
				//TODO: Impliment
				LOG("Not yet implimented");
			}
			else if (choice == ClientChoices::sendReqSymmetricKey) {
				menu.showUsers();

				MenuUser destUser = menu.chooseUser();
				
				client.connect();
				client.getSymKey(myClientId, destUser.client_id);
			}
			else if (choice == ClientChoices::sendFile) {
				//TODO: Impliment as bonous
				LOG("Not yet implimented");
			}
			else if (choice == ClientChoices::reqPullWaitingMessages) {
				//TODO: Impliment
				LOG("Not yet implimented");
				//client.connect();
				//client.pullMessages(myClientId, savedUsers);
			}
			else if (choice == ClientChoices::sendSymmetricKey) {
				if (menu.isRegistered()) {
					menu.showUsers();
					MenuUser destUser = menu.chooseUser();

					if (is_zero_filled(destUser.publicKey, S_PUBLIC_KEY)) {
						LOG("You need to get this user's public key.");
						stringstream ss;
						ss << "Would you like me to automatically get the public key of '" << destUser.username << "'?";
						if (menu.yesNoChoice(ss.str(), true)) {
							aquirePublicKey(menu, client);
						}
						else {
							LOG("Returning to main menu.");
						}
					}
					else {
						//TODO: Impliment
					}
				}
				else {
					//we can do this because server will return error every time because my username is empty (which is not allowed).
					LOG("You must register first.");
				}

				/*
				//Generate new symmetric key
				SymmetricKey symkey;
				SymmetricCrypto::generateKey(symkey);

				//Create 
				//SecureChannel sec;
				//memcpy(sec.user.client_id, dest_clientId, S_CLIENT_ID);


				client.connect();
				client.sendSymKey(myClientId, symkey, dest_clientId, savedPubKey);
				*/

			}
			else if (choice == ClientChoices::exitProgram) {
				break;
			}
			else {
				LOG("ERROR: Unknown client choice: " << static_cast<int>(choice));
			}
		}
		catch (EmptyClientsList& e) {
			LOG(e.what());
			/*
			if (menu.yesNoChoice("Would you like me to get clients list automatically?", true)) {
				//registerMyself(client, myClientId, menu);
			}
			else {
				LOG("Returning to main menu.");
			}
			*/
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