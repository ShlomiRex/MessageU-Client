#include "Client.h"
#include <boost/filesystem/operations.hpp>
#include "Debug.h"
#include "AsymmetricCrypto.h"
#include "ProtocolDefenitions.h"
#include "Menu.h"
#include "MyUser.h"

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
void requestGetClients(MyUser& me, Menu& menu, Client& client) {
	//Temporary store users from the server response
	vector<MenuUser> menuUsers;

	//Get users from server
	vector<MessageUProtocol::User> users;

	client.connect();
	ClientId myClientId;
	me.getClientId(myClientId);
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

void aquirePublicKey(MyUser& me, Menu& menu, Client& client, MenuUser& destUser) {
	ClientId myClientId;
	me.getClientId(myClientId);
	//Update 'destUser' with new public key
	client.connect();
	client.getPublicKey(myClientId, destUser.client_id, destUser.publicKey);

	//Get that public key and update menu users
	menu.setUserPublicKey(destUser.client_id, destUser.publicKey);
}

void aquirePublicKey(MyUser& me, Menu& menu, Client& client) {
	menu.showUsers();
	MenuUser destUser = menu.chooseUser();
	aquirePublicKey(me, menu, client, destUser);
}

void requestRegisterMyself(MyUser& me, Menu& menu, Client& client) {
	if (me.getUsername().size() == 0) {
		menu.readUsername();

		client.connect();
		ClientId myClientId;
		me.getClientId(myClientId);
		client.registerUser(me.getUsername(), myClientId);

		menu.setRegistered();
	}
	else {
		LOG("'" << me.getUsername() << "', your already registered!");
	}
}

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

	Menu menu;
	MyUser me;

	try {
		//Read me.info and set my username, clientid
		string myUsername = "";
		ClientId myClientId = { 0 };

		FileManager::getSavedClientId(myClientId);
		myUsername = FileManager::getSavedUsername(); //Username helps identify (for debugging and also its nice) who I am, what username I currently use.

		me.setUsername(myUsername);
		me.setClientId(myClientId);

		menu.setRegistered();
	}
	catch (InfoFileNotExistException) {
		//do nothing
	}

	//And lastly, generated symmetric key, when we want to send symmetric key.
	//vector<SecureChannel> secureChannels;


	while (true) {
		menu.show(me.getUsername());
		ClientChoices choice = menu.get_choice(me.getUsername());

		//Create client for the request.
		Client client(ip, port, CLIENT_VERSION);

		try {
			if (choice == ClientChoices::registerUser) {
				requestRegisterMyself(me, menu, client);
			}
			else if (choice == ClientChoices::reqClientList) {
				requestGetClients(me, menu, client);
			}
			else if (choice == ClientChoices::reqPublicKey) {
				aquirePublicKey(me, menu, client);
			}
			else if (choice == ClientChoices::sendMessage) {
				//TODO: Impliment
				LOG("Not yet implimented");
			}
			else if (choice == ClientChoices::sendReqSymmetricKey) {
				menu.showUsers();

				MenuUser destUser = menu.chooseUser();
				
				client.connect();
				ClientId myClientId;
				me.getClientId(myClientId);
				client.getSymKey(myClientId, destUser.client_id);
			}
			else if (choice == ClientChoices::sendFile) {
				//TODO: Impliment as bonous
				LOG("Not yet implimented");
			}
			else if (choice == ClientChoices::reqPullWaitingMessages) {
				if (menu.isRegistered() == false) {
					throw NotRegistered();
				}
				//Get uses saved in memory
				auto users = menu.getUsers();

				if (users.size() == 0) {
					throw EmptyClientsList();
				}

				//Create vector of users (without public key) to call pull messages
				vector<MessageUProtocol::User> castUsers;
				for (const auto& x : users) {
					//Read google, push_back copies User, so it won't be freed after loop.
					MessageUProtocol::User tmpUser;
					memcpy(tmpUser.client_id, x.client_id, S_CLIENT_ID);
					memcpy(tmpUser.username, x.username, S_USERNAME);
					castUsers.push_back(tmpUser);
				}

				//Let client do the rest
				client.connect();
				ClientId myClientId;
				me.getClientId(myClientId);
				const vector<MessageResponse>* messages = client.pullMessages(myClientId, castUsers);
				if (messages != nullptr) {
					for (const auto& msg : *messages) {
						MessageTypes _type = (MessageTypes)msg.msgType;
						if (_type == MessageTypes::sendSymmetricKey) {
							//Save the symmetric key

							string symmkey_cipher(msg.msgContent);
							PublicKey myPubKey;
							me.getPublicKey(myPubKey);
							string plainSymmKey = AsymmetricCrypto::decrypt(symmkey_cipher, myPubKey);

							LOG("Symmetric key (" << msg.msgSize << " bytes):");
							hexify((const unsigned char*)msg.msgContent, msg.msgSize);

							SymmetricKey symmkey;
							memcpy(symmkey, msg.msgContent, S_SYMMETRIC_KEY); //TODO: I know msg.msgContent is greater than S_SYMMETRIC_KEY, we need to send correct cipher, not "Super Secret"
							menu.setUserSymmKey(msg.sender.client_id, symmkey);
						}
					}
					//Free vector pointer
					delete messages;
				}
				LOG("Finished handling pull messages request.");
			}
			else if (choice == ClientChoices::sendSymmetricKey) {
				if (menu.isRegistered() == false) {
					throw NotRegistered();
				}

				menu.showUsers();
				MenuUser destUser = menu.chooseUser();

				if (is_zero_filled(destUser.publicKey, S_PUBLIC_KEY)) {
					throw EmptyPublicKey(destUser);
				}

				//Generate new symmetric key
				SymmetricKey symkey = { 0 };
				//SymmetricCrypto::generateKey(symkey);

				//Create 
				//SecureChannel sec;
				//memcpy(sec.user.client_id, dest_clientId, S_CLIENT_ID);

				//TODO: Send a secret message first, test it works to decrypt it, and if it works, generate symm key and send it instead
				strncpy_s(symkey, "Super Secret", 13);

				client.connect();
				//We encrypt with destUser's public key
				ClientId myClientId;
				me.getClientId(myClientId);
				client.sendSymKey(myClientId, symkey, destUser.client_id, destUser.publicKey);
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
			
			if (menu.yesNoChoice("Would you like me to get clients list automatically?", true)) {
				requestGetClients(me, menu, client);
			}
			else {
				LOG("Returning to main menu.");
			}
		}
		catch (NotRegistered& e) {
			LOG(e.what());

			if (menu.yesNoChoice("Would you like me to register you now?", true)) {
				requestRegisterMyself(me, menu, client);
			}
			else {
				LOG("Returning to main menu.");
			}
		}
		catch (EmptyPublicKey& e) {
			LOG(e.what());

			auto destUser = e.getDestUser();

			stringstream ss;
			ss << "Would you like me to automatically get the public key of '" << destUser.username << "'?";
			if (menu.yesNoChoice(ss.str(), true)) {
				aquirePublicKey(me, menu, client, destUser);
			}
			else {
				LOG("Returning to main menu.");
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