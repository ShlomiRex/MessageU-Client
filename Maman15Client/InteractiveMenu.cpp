#include "InteractiveMenu.h"

#define LOG(msg) cout << msg << endl;

using namespace std;

InteractiveMenu::InteractiveMenu() {

}

void InteractiveMenu::show_menu() {
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

ClientChoices InteractiveMenu::get_choice() {
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
				return ClientChoices::reqWaitingMessages;
			case 50:
				return ClientChoices::sendText;
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
			show_menu();
		}
	}
}

string InteractiveMenu::getUsernameForRegister() {
	string username = "";
	while (true) {
		LOG("Please type desired username for registeration. (non-empty and maximum " << S_USERNAME << " characters)");
		getline(cin, username); //for now, allow any string as username. if server is not happy we get error response anyway.
		if (username.size() >= 1 && username.size() <= S_USERNAME)
			break;
	}
	return username;
}
