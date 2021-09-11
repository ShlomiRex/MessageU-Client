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

void InteractiveMenu::getClientId(char buffer[S_CLIENT_ID])
{
	LOG("Please type client id (in hex, 16 bytes, for example: '66 c1 81 ...'):");
	string line;

	while (true) {
		getline(cin, line);

		try {
			//Remove all spaces
			line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
			
			//Check exact size
			if (line.size() == S_CLIENT_ID * 2) {
				//Check hex conversion (for example, 'G' letter is not hex. Or any other character like '/'.)
				try {
					string unhex = boost::algorithm::unhex(line);
					std::copy(unhex.begin(), unhex.end(), buffer);
					break;
				}
				catch (exception& e) {
					LOG(e.what());
					LOG("Couldn't convert input to valid hex string. Please try again.");
				}
			}
			else {
				LOG("Please type valid 16 bytes hex.");
			}
		}
		catch (exception& e) {
			LOG(e.what());
			LOG("Couldn't remove spaces from the input. Please try again.")
		}
	}



}
