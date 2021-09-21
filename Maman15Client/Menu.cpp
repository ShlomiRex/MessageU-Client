#include "Menu.h"

using namespace std;
using namespace MessageUProtocol;

Menu::Menu() : registered(false) {

}

void Menu::setUserPublicKey(const MessageUProtocol::ClientId& userClientId, const MessageUProtocol::PublicKey& pubkey)
{
	for (auto& x : users) {
		if (buffer_compare(x.client_id, userClientId, S_CLIENT_ID)) {
			memcpy(x.publicKey, pubkey, S_PUBLIC_KEY);
			return;
		}
	}
	throw MenuUserNotFound();
}

void Menu::setUserSymmKey(const MessageUProtocol::ClientId& userClientId, const MessageUProtocol::SymmetricKey& symmkey)
{
	for (auto& x : users) {
		if (buffer_compare(x.client_id, userClientId, S_CLIENT_ID)) {
			memcpy(x.symmKey, symmkey, S_SYMMETRIC_KEY);
			return;
		}
	}
	throw MenuUserNotFound();
}

void Menu::setRegistered()
{
	registered = true;
}

bool Menu::isRegistered()
{
	return registered;
}

const std::vector<MenuUser> Menu::getUsers()
{
	return users;
}

void Menu::show(const string& myUsername) const {
	if ((string)(myUsername) != "") {
		LOG("Hello " << myUsername << "!");
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

void Menu::showUsers() const
{
	if (users.size() != 0) {
		LOG("Available users:");
		for (size_t i = 0; i < users.size(); i++) {
			const auto& user = users.at(i);
			string clientId_str = hexify_str(user.client_id, S_CLIENT_ID);

			LOG("\t" << (i + 1) << ") Username: " << user.username);
			LOG("\tClient ID: " << clientId_str);

			//Check public key is not zeroes array
			if (is_zero_filled(user.publicKey, S_PUBLIC_KEY)) {
				LOG("\tPublic key: Not aquired");
			}
			else {
				LOG("\tPublic key: Aquired");
			}

			//Check symm key is not zeroes array
			if (is_zero_filled(user.symmKey, S_SYMMETRIC_KEY)) {
				LOG("\tSymmetric key: Not aquired");
			}
			else {
				LOG("\tSymmetric key: Aquired");
			}
			LOG("");
		}
	}
	else {
		LOG("No available users.");
	}
}

ClientChoices Menu::get_choice(const string& myUsername) const
{
	string line;

	while (true) {
		try {
			getline(cin, line);
			if (is_number(line)) {
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
			else {
				throw invalid_argument("You must choose a number.");
			}

		}
		catch (exception& e) {
			LOG(e.what());
			LOG("Please chooce valid entry.\n\n");
			show(myUsername);
		}
	}
}

string Menu::readUsername()
{
	string username = "";
	while (true) {
		LOG("Please type desired username (non-empty and maximum " << S_USERNAME << " characters): ");
		getline(cin, username); //for now, allow any string as username. if server is not happy we get error response anyway.
		if (username.size() >= 1 && username.size() <= S_USERNAME)
			return username;
	}
}

const MenuUser Menu::chooseUser() const
{
	//Check saved clients vector
	if (users.size() == 0) {
		throw EmptyClientsList();
	}

	LOG("I need to know destination user to send request to.");
	LOG("Please type username(e.g. 'Shlomi'), user number(e.g. '1'), or client id (in hex, 16 bytes, e.g. '66 c1 81 ...'): ");
	string line;

	while (true) {
		getline(cin, line);

		//Try number
		try {
			DEBUG("Trying to parse input as user number");
			//Check is number first

			//int user_number = stoi(line); //Never use it to check if number. If line is hex: '8f 87 48...' it converts first character only to 8 instead of throwing error.
			if (is_number(line)) {
				int user_number = stoi(line); //Now we can use it, because we are sure it is a number.
				for (size_t i = 0; i < users.size(); i++) {
					if (user_number == (i + 1)) {
						const auto& x = users.at(i);
						LOG("You chose user number: " << user_number << " with username: " << x.username);
						auto found = users.at(i).client_id;
						return x;
					}
				}
				LOG("Please type valid user number from client list.");
				continue;
			}
			else {
				//do nothing, continue to parse maybe username or hex
			}
		}
		catch (...) {
			DEBUG("Couldn't parse input to number.");
		}

		//Try username
		try {
			DEBUG("Trying to parse input as username");
			for (const auto& x : users) {
				string username = x.username;
				if (username == line) {
					LOG("You chose username: " << x.username);
					return x;
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
			//Multiply by 2 because 1 hex = 2 chars
			if (line.size() == S_CLIENT_ID * 2) {
				//Check hex conversion (for example, 'G' letter is not hex. Or any other character like '/'.)
				try {
					string unhex = boost::algorithm::unhex(line);

					for (const auto& x : users) {
						//TODO: Compare client id in possible choices to input
						string client_id_str = x.client_id;
						if (strncmp(client_id_str.c_str(), unhex.c_str(), S_CLIENT_ID) == 0) {
							return x;
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

bool Menu::yesNoChoice(string prompt, bool yesIsDefaultChoice) {
	string defaultStr;
	if (yesIsDefaultChoice) {
		defaultStr = " [Y/n]";
	}
	else {
		defaultStr = " [y/N]";
	}
	LOG(prompt << defaultStr);

	string choice;
	getline(cin, choice);

	//Yes choice
	if (choice == "Y" || choice == "y") {
		return true;
	}
	//No choice
	else if (choice == "N" || choice == "n") {
		return false;
	}
	//Default choice
	else {
		return yesIsDefaultChoice;
	}
}

