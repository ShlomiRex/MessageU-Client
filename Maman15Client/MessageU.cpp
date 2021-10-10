#include "MessageU.h"

#define DEBUG_PREFIX "[MessageU] "

using namespace std;
using namespace MessageUProtocol;

int MessageU::findUser(const MessageUProtocol::ClientId& clientId) const
{
	for (size_t i = 0; i < users.size(); i++) {
		ClientId _clientId;
		users.at(i).getClientId(_clientId);

		bool same = buffer_compare(_clientId, clientId, S_CLIENT_ID);
		if (same) {
			return i;
		}
	}
	return -1;
}

void MessageU::readInfoFile() {
	try {
		//Read me.info and set my username, clientid
		string myUsername = "";
		ClientId myClientId = { 0 };

		//Read client id
		FileManager::getSavedClientId(myClientId);
		me.setClientId(myClientId);

		//Read username
		myUsername = FileManager::getSavedUsername(); //Username helps identify (for debugging and also its nice) who I am, what username I currently use.
		if (myUsername.size() > 0 && myUsername.size() <= S_USERNAME) {
			me.setUsername(myUsername);
		}

		//Read private key
		string privateKeyFromFile = FileManager::getSavedPrivateKey();
		string privkey_str = Base64Wrapper::decode(privateKeyFromFile);
		me.setPrivateKey(privkey_str);

		me.setRegistered();
	}
	catch (InfoFileNotExistException) {
		//do nothing, not registered
	}
}

MessageU::MessageU(string ip, string port) : ip(ip), port(port) {
	readInfoFile();
}

void MessageU::start()
{
	while (true) {
		string myUsername = me.getUsername();
		Menu::show(myUsername);
		ClientChoices choice = Menu::get_choice(myUsername);

		//Create client for the request. (one per choice)
		Client client(ip, port, CLIENT_VERSION);

		try {
			if (choice == ClientChoices::registerUser) {
				registerChoice(client);
			}
			else if (choice == ClientChoices::reqClientList) {
				getClientsChoice(client);
			}
			else if (choice == ClientChoices::reqPublicKey) {
				getPublicKeyChoice(client);
			}
			else if (choice == ClientChoices::sendMessage) {
				sendMessageChoice(client);
			}
			else if (choice == ClientChoices::sendReqSymmetricKey) {
				sendReqSymmKeyChoice(client);
			}
			else if (choice == ClientChoices::reqPullWaitingMessages) {
				pullMessagesChoice(client);
			}
			else if (choice == ClientChoices::sendSymmetricKey) {
				sendSymmKeyChoice(client);
			}
			else if (choice == ClientChoices::sendFile) {
				sendFileChoice(client);
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

			if (Menu::yesNoChoice("Would you like me to get clients list automatically?", true)) {
				getClientsChoice(client);
			}
			else {
				LOG("Returning to main Menu");
			}
		}
		catch (NotRegistered& e) {
			LOG(e.what());

			if (Menu::yesNoChoice("Would you like me to register you now?", true)) {
				registerChoice(client);
			}
			else {
				LOG("Returning to main Menu");
			}
		}
		catch (EmptyPublicKey& e) {
			LOG(e.what());

			auto destUser = e.getDestUser();

			stringstream ss;
			ss << "Would you like me to automatically get the public key of '" << destUser.getUsername() << "'?";
			if (Menu::yesNoChoice(ss.str(), true)) {
				aquirePublicKey(client, destUser);
			}
			else {
				LOG("Returning to main Menu");
			}
		}
		catch (EmptySymmKey& e) {
			LOG(e.what());
			//To get symmetric key, user must first get public key.
			//Then send symm key request.
			//Then pull messages.
			//Then get symm key.

			//It can't be done automatically. So we only print the error.
		}
		catch (exception& e) {
			LOG(e.what());
		}


		cout << "\n\n\n";
	}
}

void MessageU::registerChoice(Client& client)
{
	string current_username = me.getUsername();
	if (current_username.size() == 0) {
		string new_username = Menu::readUsername();

		client.connect();
		ClientId myClientId;
		me.getClientId(myClientId);
		client.registerUser(new_username, myClientId);

		readInfoFile();
	}
	else {
		LOG("'" << current_username << "', your already registered!");
	}
}

void MessageU::getClientsChoice(Client& client)
{
	if (users.size() > 0) {
		// Maybe we just want to see what we got. It's a nice touch.
		Menu::showUsers(&users);

		if (Menu::yesNoChoice("Warning: getting clients again will result in wipe of saved client's keys, usernames and ids! Are you sure?", false)) {
			goto get_users;
		}
		else {
			LOG("Returning to main Menu");
			return;
		}
	}

get_users:
	//Temporary store usersGot from the server response
	vector<MessageU_User> newUsers;

	//Get usersGot from server
	vector<MessageUProtocol::User> usersGot;

	client.connect();
	ClientId myClientId;
	me.getClientId(myClientId);
	client.getClients(myClientId, &usersGot);

	for (const auto& x : usersGot) {
		//It's ok, vector does the copy operator, so it won't be freed after loop,
		MessageU_User user;
		user.setClientId(x.client_id);
		user.setUsername((char*)x.username);

		newUsers.push_back(user);
	}

	if (newUsers.size() > 0) {
		//Update our saved users in memory
		users.clear();
		users.assign(newUsers.begin(), newUsers.end());

		LOG("Users saved in memory for later use.");
	}
}

void MessageU::getPublicKeyChoice(Client& client)
{
	Menu::showUsers(&users);
	MessageU_User destUser = Menu::chooseUser(&users);
	aquirePublicKey(client, destUser);
}

void MessageU::sendMessageChoice(Client& client)
{
	Menu::showUsers(&users);

	//Get destination
	auto destUser = Menu::chooseUser(&users);
	ClientId destClientId;
	destUser.getClientId(destClientId);

	//Get symm key. Check if we have the user's symm key.
	SymmetricKey symmkey;
	destUser.getSymmetricKey(symmkey);
	if (is_zero_filled(symmkey, S_SYMMETRIC_KEY)) {
		throw EmptySymmKey();
	}

	//Get the message content to send.
	string text = Menu::readText();

	//Get my client id
	ClientId myClientId;
	me.getClientId(myClientId);

	//Go
	client.connect();
	client.sendText(myClientId, destClientId, symmkey, text);
}

void MessageU::sendReqSymmKeyChoice(Client& client)
{
	Menu::showUsers(&users);

	MessageU_User destUser = Menu::chooseUser(&users);

	client.connect();
	ClientId myClientId;
	me.getClientId(myClientId);

	ClientId destClientId;
	destUser.getClientId(destClientId);
	client.getSymKey(myClientId, destClientId);
}

void MessageU::pullMessagesChoice(Client& client)
{
	if (me.isRegistered() == false) {
		throw NotRegistered();
	}

	if (users.size() == 0) {
		throw EmptyClientsList();
	}

	//Let client do the rest - get response vector
	client.connect();

	ClientId myClientId;
	me.getClientId(myClientId);
	const vector<MessageResponse>* messages = client.pullMessages(myClientId, users);

	DEBUG("Parsing messages...");
	if (messages != nullptr) {
		for (const auto& msg : *messages) {
			MessageTypes _type = (MessageTypes)msg.msgType;
			if (_type == MessageTypes::sendSymmetricKey) {
				DEBUG("Found message of type 'sendSymmetricKey'");
                
				string symmkey_cipher(msg.msgContent, msg.msgSize);

				//Read and decode private key
				DEBUG("Decoding my private key from info file...");
				string saved_priv_key = FileManager::getSavedPrivateKey();
				string privkey = Base64Wrapper::decode(saved_priv_key);

				//Decrypt message
				DEBUG("Decrypting message content (" << msg.msgSize << " bytes)...");
				RSAPrivateWrapper rsaPrivWrapper(privkey);
				string plain_symmKey = rsaPrivWrapper.decrypt(symmkey_cipher);
				DEBUG("Decrypt success! Plain text is " << plain_symmKey.size() << " bytes.");

				//Convert to array
				SymmetricKey symmKey;
				str_to_symmKey(plain_symmKey, symmKey);

#ifdef DEBUGGING
				DEBUG("Decrypted symmetric key:");
				hexify(symmKey, S_SYMMETRIC_KEY);
#endif

				//Find user with sender's client id
				int index = findUser(msg.sender.client_id);
				if (index < 0) {
					throw UserNotFound();
				}

				//Set symmetric key of the sender
				users.at(index).setSymmKey(symmKey);

				//Free content pointer
				delete[] msg.msgContent;
			}
		}
		//Free vector pointer
		delete messages;
	}
	DEBUG("Finished handling pull messages request.");
}

void MessageU::sendSymmKeyChoice(Client& client)
{
	if (me.isRegistered() == false) {
		throw NotRegistered();
	}

	Menu::showUsers(&users);
	MessageU_User destUser = Menu::chooseUser(&users);

	PublicKey destPubKey = { 0 };
	destUser.getPublicKey(destPubKey);

	if (is_zero_filled(destPubKey, S_PUBLIC_KEY)) {
		throw EmptyPublicKey(destUser);
	}

	//Generate new symmetric key
	SymmetricKey symkey = { 0 };
	unsigned char buff[S_SYMMETRIC_KEY];
	AESWrapper aes(AESWrapper::GenerateKey(buff, S_SYMMETRIC_KEY), S_SYMMETRIC_KEY);
	memcpy(symkey, buff, S_SYMMETRIC_KEY);

#ifdef DEBUGGING
	DEBUG("Generated symm key (" << S_SYMMETRIC_KEY << " bytes):");
	hexify((const unsigned char*)symkey, S_SYMMETRIC_KEY);
#endif

	//Save symm key so we can use it later. Associate symm key with destination client
	ClientId destUserClientId;
	destUser.getClientId(destUserClientId);
	int index = findUser(destUserClientId);
	if (index < 0) {
		throw UserNotFound();
	}

	//Send request
	client.connect();
	ClientId myClientId = { 0 };
	me.getClientId(myClientId);
	client.sendSymKey(myClientId, symkey, destUserClientId, destPubKey); 	//We encrypt with destUser's public key

	//Set symm key for this dest user, key exchange success
	users.at(index).setSymmKey(symkey);
}

void MessageU::aquirePublicKey(Client& client, MessageU_User& destUser) {
	DEBUG("Getting public key...");
	ClientId myClientId;
	me.getClientId(myClientId);

	//Update 'destUser' with new public key
	client.connect();
	ClientId destClientId;
	destUser.getClientId(destClientId);
	PublicKey destPubKey = { 0 };
	client.getPublicKey(myClientId, destClientId, destPubKey);

	//Get that public key and update menu usersGot
	int index = findUser(destClientId);
	if (index < 0) {
		throw UserNotFound();
	}
	users.at(index).setPublicKey(destPubKey);
	LOG("Got public key!");
}

void MessageU::sendFileChoice(Client& client)
{
	//Get destination
	Menu::showUsers(&users);
	auto destUser = Menu::chooseUser(&users);
	ClientId destClientId;
	destUser.getClientId(destClientId);

	//Get symm key
	SymmetricKey symmkey;
	destUser.getSymmetricKey(symmkey);
	if (is_zero_filled(symmkey, S_SYMMETRIC_KEY)) {
		throw EmptySymmKey();
	}

	//Get file
	string filepath = Menu::chooseFile();
	DEBUG("File chosen: " << filepath);
	size_t filesize = boost::filesystem::file_size(filepath);

	//Get my client id
	ClientId myClientId;
	me.getClientId(myClientId);

	//Open read stream
	ifstream filestream(filepath, std::ios::binary);

	//Go
	client.connect();
	client.sendFile(myClientId, symmkey, destClientId, filesize, filestream);

	//Close file stream
	filestream.close();
}
