#include "InteractiveMenu.h"

using namespace std;

void InteractiveMenu::show_menu(string myUsername, ClientId* myClientId) {
	if (myUsername.size() > 0) {
		LOG("Hello " << myUsername << "!");
	}

	if (myClientId != nullptr) {
		DEBUG("My client id: ");
#ifdef DEBUGGING
		hexify((const unsigned char*)myClientId, S_CLIENT_ID);
#endif
	}

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

Menu::ClientChoices InteractiveMenu::get_choice() {
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
				return Menu::ClientChoices::registerUser;
			case 20:
				return Menu::ClientChoices::reqClientList;
			case 30:
				return Menu::ClientChoices::reqPublicKey;
			case 40:
				return Menu::ClientChoices::reqPullWaitingMessages;
			case 50:
				return Menu::ClientChoices::sendText;
			case 51:
				return Menu::ClientChoices::sendReqSymmetricKey;
			case 52:
				return Menu::ClientChoices::sendSymmetricKey;
			case 0:
				return Menu::ClientChoices::exitProgram;
			default:
				throw invalid_argument("No such choice.");
			}
		}
		catch (exception& e) {
			LOG(e.what());
			LOG("Please chooce valid entry.\n\n");
			show_menu("", nullptr);
		}
	}
}

string InteractiveMenu::readUsername() {
	string username = "";
	while (true) {
		LOG("Please type desired username (non-empty and maximum " << S_USERNAME << " characters): ");
		getline(cin, username); //for now, allow any string as username. if server is not happy we get error response anyway.
		if (username.size() >= 1 && username.size() <= S_USERNAME)
			break;
	}
	return username;
}

void InteractiveMenu::getClientId(ClientId result, vector<User>* possibleChoices)
{
	//Check saved clients vector
	if (possibleChoices->size() == 0) {
		throw EmptyClientsList();
	}

	LOG("I need to know the client ID.");
	LOG("Please type username(e.g. 'Shlomi'), user number(e.g. '1'), or client id (in hex, 16 bytes, e.g. '66 c1 81 ...'): ");
	string line;

	while (true) {
		getline(cin, line);

		//Try number
		try {
			DEBUG("Trying to parse input as user number");
			int user_number = stoi(line);
			for (size_t i = 0; i < possibleChoices->size(); i++) {
				if (user_number == (i + 1)) {
					const auto& x = possibleChoices->at(i);
					LOG("You chose user number: " << user_number << " with username: " << x.username);
					auto found = possibleChoices->at(i).client_id;
					memcpy(result, found, S_CLIENT_ID);
					return;
				}
			}
			LOG("Please type valid user number from client list.");
			continue;
		}
		catch (...) {
			DEBUG("Couldn't parse input to number.");
		}

		//Try username
		try {
			DEBUG("Trying to parse input as username");
			for (const auto& x : *possibleChoices) {
				string username = x.username;
				if (username == line) {
					LOG("You chose username: " << x.username);
					memcpy(result, x.client_id, S_CLIENT_ID);
					return;
				}
			}
			DEBUG("Couldn't find username in vector.")
		}
		catch (...) {
			DEBUG("Couldn't parse input as username");
		}

		//Try hex
		try {
			DEBUG("Trying to parse input as hex");
			//Remove all spaces
			line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
			
			//Check exact size
			if (line.size() == S_CLIENT_ID * 2) {
				//Check hex conversion (for example, 'G' letter is not hex. Or any other character like '/'.)
				try {
					string unhex = boost::algorithm::unhex(line);

					for (const auto& x : *possibleChoices) {
						//TODO: Compare client id in possible choices to input
						string client_id_str = x.client_id;
						if (client_id_str == unhex) {
							std::copy(unhex.begin(), unhex.end(), result);
							return;
						}
					}

					DEBUG("Could not find clientId in the clients list.");
				}
				catch (exception& e) {
					LOG(e.what());
					LOG("Couldn't convert input to valid hex string. Please try again.");
				}
			}
			else {
				LOG("Please type valid username, user number or 16 bytes hex.");
			}
		}
		catch (exception& e) {
			LOG(e.what());
			LOG("Couldn't remove spaces from the input. Please try again.")
		}
	}
}

string InteractiveMenu::readText() {
	string text = "";
	while (true) {
		LOG("Please type desired text (at least 1 character):");
		getline(cin, text); 
		if (text.size() >= 1)
			break;
	}
	return text;
}