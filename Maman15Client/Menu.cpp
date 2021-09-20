#include "Menu.h"

using namespace std;

Menu::Menu() {
	memset(me.client_id, 0, S_CLIENT_ID);
	memset(me.username, 0, S_USERNAME);
}

Menu::~Menu() {

}

void Menu::setUsername(string& username)
{
	memcpy(me.username, username.c_str(), S_USERNAME);
}

void Menu::setClientId(MessageUProtocol::ClientId& clientId)
{
	memcpy(me.client_id, clientId, S_CLIENT_ID);
}

string Menu::getUsername()
{
	return me.username;
}

void Menu::getClientId(MessageUProtocol::ClientId result)
{
	memcpy(result, me.client_id, S_CLIENT_ID);
}

void Menu::show() {
	if ((string)(me.username) != "") {
		LOG("Hello " << me.username << "!");
	}

#ifdef DEBUGGING
	if (myClientId != nullptr) {
		DEBUG("My client id: ");
		hexify((const unsigned char*)me.client_id, S_CLIENT_ID);
	}
#endif


	LOG("MessageU client at your service.\n");

	LOG("10) Register");
	LOG("20) Request for client list");
	LOG("30) Request for public key");
	LOG("40) Request for waiting messages");
	LOG("50) Send a text message");
	LOG("51) Send a request for symmetric key");
	LOG("52) Send your symmetic key");
	LOG("0) Exit client");
}

ClientChoices Menu::get_choice()
{
	string line;

	while (true) {
		try {
			getline(cin, line);
			int __choice = stoi(line); //throws invalid argument
			if (__choice < 0) {
				throw invalid_argument("Choice is negative number. No such choice.");
			}
			switch (__choice) {
			case 10:
				return ClientChoices::registerUser;
			case 20:
				return ClientChoices::reqClientList;
			case 30:
				return ClientChoices::reqPublicKey;
			case 40:
				return ClientChoices::reqPullWaitingMessages;
			case 50:
				return ClientChoices::sendMessage;
			case 51:
				return ClientChoices::sendReqSymmetricKey;
			case 52:
				return ClientChoices::sendSymmetricKey;
			case 0:
				return ClientChoices::exitProgram;
			default:
				throw invalid_argument("No such choice.");
			}
		}
		catch (exception& e) {
			LOG(e.what());
			LOG("Please chooce valid entry.\n\n");
			show();
		}
	}
}

void Menu::readAndSetMyUsername()
{
	string username = "";
	while (true) {
		LOG("Please type desired username (non-empty and maximum " << S_USERNAME << " characters): ");
		getline(cin, username); //for now, allow any string as username. if server is not happy we get error response anyway.
		if (username.size() >= 1 && username.size() <= S_USERNAME)
			break;
	}
	setUsername(username);
}

