#include "MessageU.h"

using namespace std;
using namespace MessageUProtocol;

void updateUsers(Menu& menuobj, vector<MenuUser>* serverResponse) {
	//Clear current users from memory
	menuobj.users.clear();
	//Save new users
	menuobj.users.assign(serverResponse->begin(), serverResponse->end());
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

MessageU::MessageU(string ip, string port) : ip(ip), port(port) {
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
		//do nothing, not registered
	}
}

void MessageU::start()
{
	while (true) {
		menu.show(me.getUsername());
		ClientChoices choice = menu.get_choice(me.getUsername());

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
}

void MessageU::registerChoice(Client& client)
{
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

void MessageU::getClientsChoice(Client& client)
{
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

void MessageU::getPublicKeyChoice(Client& client)
{
	menu.showUsers();
	MenuUser destUser = menu.chooseUser();
	aquirePublicKey(me, menu, client, destUser);
}

void MessageU::sendMessageChoice(Client& client)
{
	//TODO: Impliment
	LOG("Not yet implimented");
}

void MessageU::sendReqSymmKeyChoice(Client& client)
{
	menu.showUsers();

	MenuUser destUser = menu.chooseUser();

	client.connect();
	ClientId myClientId;
	me.getClientId(myClientId);
	client.getSymKey(myClientId, destUser.client_id);
}

void MessageU::sendFileChoice(Client& client)
{
	//TODO: Impliment as bonous
	LOG("Not yet implimented");
}

void MessageU::pullMessagesChoice(Client& client)
{
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

void MessageU::sendSymmKeyChoice(Client& client)
{
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
