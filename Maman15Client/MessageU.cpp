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

		PrivateKey privKey = { 0 };
		str_to_pubKey(privkey_str, privKey);
		me.setPrivateKey(privKey);

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
		menu.show(myUsername);
		ClientChoices choice = menu.get_choice(myUsername);

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
			else if (choice == ClientChoices::sendFile) {
				sendFileChoice(client);
			}
			else if (choice == ClientChoices::reqPullWaitingMessages) {
				pullMessagesChoice(client);
			}
			else if (choice == ClientChoices::sendSymmetricKey) {
				sendSymmKeyChoice(client);
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
				getClientsChoice(client);
			}
			else {
				LOG("Returning to main menu.");
			}
		}
		catch (NotRegistered& e) {
			LOG(e.what());

			if (menu.yesNoChoice("Would you like me to register you now?", true)) {
				registerChoice(client);
			}
			else {
				LOG("Returning to main menu.");
			}
		}
		catch (EmptyPublicKey& e) {
			LOG(e.what());

			auto destUser = e.getDestUser();

			stringstream ss;
			ss << "Would you like me to automatically get the public key of '" << destUser.getUsername() << "'?";
			if (menu.yesNoChoice(ss.str(), true)) {
				aquirePublicKey(client, destUser);
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
}

void MessageU::registerChoice(Client& client)
{
	string current_username = me.getUsername();
	if (current_username.size() == 0) {
		string new_username = menu.readUsername();

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
		if (menu.yesNoChoice("Warning: getting clients again will result in wipe of saved client's keys, usernames and ids! Are you sure?", false)) {
			goto get_users;
		}
		else {
			LOG("Returning to main menu.");
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
	menu.showUsers(&users);
	MessageU_User destUser = menu.chooseUser(&users);
	aquirePublicKey(client, destUser);
}

void MessageU::sendMessageChoice(Client& client)
{
	//TODO: Impliment
	LOG("Not yet implimented");
}

void MessageU::sendReqSymmKeyChoice(Client& client)
{
	menu.showUsers(&users);

	MessageU_User destUser = menu.chooseUser(&users);

	client.connect();
	ClientId myClientId;
	me.getClientId(myClientId);

	ClientId destClientId;
	destUser.getClientId(destClientId);
	client.getSymKey(myClientId, destClientId);
}

void MessageU::sendFileChoice(Client& client)
{
	//TODO: Impliment as bonous
	LOG("Not yet implimented");
}

void MessageU::pullMessagesChoice(Client& client)
{
	if (me.isRegistered() == false) {
		throw NotRegistered();
	}

	if (users.size() == 0) {
		throw EmptyClientsList();
	}

	//Create vector of usersGot (without public key) to call pull messages
	vector<MessageUProtocol::User> castUsers;
	for (const auto& x : users) {
		ClientId xClientId;
		x.getClientId(xClientId);

		//Read google, push_back copies User, so it won't be freed after loop.
		MessageUProtocol::User tmpUser;
		memcpy(tmpUser.client_id, xClientId, S_CLIENT_ID);
		memcpy(tmpUser.username, x.getUsername().c_str(), S_USERNAME);
		castUsers.push_back(tmpUser);
	}

	//Let client do the rest - get response vector
	client.connect();

	ClientId myClientId;
	me.getClientId(myClientId);
	const vector<MessageResponse>* messages = client.pullMessages(myClientId, castUsers);

	if (messages != nullptr) {
		for (const auto& msg : *messages) {
			MessageTypes _type = (MessageTypes)msg.msgType;
			if (_type == MessageTypes::sendSymmetricKey) {
				//Save the symmetric key
				//NOTE: WE HAVE THE SAME PROBLEM JUST AS SEND SYMM KEY! WE NEED THE STRING TO CONTAIN NULL TERMINATORS.
				//string symmkey_cipher(msg.msgContent);
				string symmkey_cipher = buffer_to_str((unsigned char*)msg.msgContent, msg.msgSize);

				//Read and decode private key
				string saved_priv_key = FileManager::getSavedPrivateKey();
				string privkey = Base64Wrapper::decode(saved_priv_key);

				//Decrypt message
				RSAPrivateWrapper rsaPrivWrapper(privkey);
				string plain_symmKey = rsaPrivWrapper.decrypt(symmkey_cipher);
				
				//Cast message content to symm key
				//SymmetricKey symmkey;
				//memcpy(symmkey, plain.c_str(), S_SYMMETRIC_KEY); //TODO: I know msg.msgContent is greater than S_SYMMETRIC_KEY, we need to send correct cipher, not "Super Secret"

				//Find user with sender's client id
				int index = findUser(msg.sender.client_id);
				if (index < 0) {
					throw UserNotFound();
				}
				//Set symmetric key of the sender
				//users.at(index).setSymmKey(symmkey);
				SymmetricKey symmKey;
				str_to_symmKey(plain_symmKey, symmKey);
				users.at(index).setSymmKey(symmKey);
			}
		}
		//Free vector pointer
		delete messages;
	}
	LOG("Finished handling pull messages request.");
}

void MessageU::sendSymmKeyChoice(Client& client)
{
	if (me.isRegistered() == false) {
		throw NotRegistered();
	}

	menu.showUsers(&users);
	MessageU_User destUser = menu.chooseUser(&users);

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
	LOG("Generated symm key (" << S_SYMMETRIC_KEY << " bytes):");
	hexify((const unsigned char*)symkey, S_SYMMETRIC_KEY);

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
}

