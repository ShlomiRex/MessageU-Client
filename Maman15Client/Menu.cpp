#include "Menu.h"

using namespace std;
using namespace MessageUProtocol;

void Menu::show(const string& myUsername) {
	if ((string)(myUsername) != "") {
		LOG("Hello '" << myUsername << "'!");
	}

	LOG("MessageU client at your service.\n");

	LOG("10) Register");
	LOG("20) Request for client list");
	LOG("30) Request for public key");
	LOG("40) Request for waiting messages");
	LOG("50) Send a text message");
	LOG("51) Send a request for symmetric key");
	LOG("52) Send your symmetic key");
	LOG("53) Send file");
	LOG("0) Exit client");
}

void Menu::showUsers(const vector<MessageU_User>* availableUsers)
{
	if (availableUsers->size() != 0) {
		LOG("Available users:");
		for (size_t i = 0; i < availableUsers->size(); i++) {
			const auto& user = availableUsers->at(i);

			LOG("\t" << (i + 1) << ") Username: \t\t" << user.getUsername());

			// A decision was made: don't show public key, symm key, client id to user. Only in debugging mode.
			// 1) User doesn't need to know the inner workings.
			// 2) Possible symm key leak.

#ifdef DEBUGGING
			ClientId clientId;
			user.getClientId(clientId);
			string clientId_str = hexify_str(clientId, S_CLIENT_ID);
			LOG("\tClient ID: \t\t" << clientId_str);
#else
			LOG("\tClient ID: \t\tAquired");
#endif


			//Check public key is not zeroes array
			PublicKey pubkey = { 0 };
			user.getPublicKey(pubkey);

			if (is_zero_filled(pubkey, S_PUBLIC_KEY)) {
				LOG("\tPublic key: \t\tNot aquired");
			}
			else {
#ifdef DEBUGGING
                string pubkey_str((char*)pubkey, S_PUBLIC_KEY);
                pubkey_str = pubkey_str.substr(0, SHOW_PUBKEY_MAX_CHARACTERS);
				pubkey_str = hexify_str((unsigned char*)pubkey_str.c_str(), pubkey_str.size());
				LOG("\tPublic key: \t\t" << pubkey_str << "... (" << S_PUBLIC_KEY << " bytes)");
#else
				LOG("\tPublic key: \t\tAquired");
#endif
			}

			//Check symm key is not zeroes array
			SymmetricKey symmkey = { 0 };
			user.getSymmetricKey(symmkey);
			if (is_zero_filled(symmkey, S_SYMMETRIC_KEY)) {
				LOG("\tSymmetric key: \t\tNot aquired");
			}
			else {
#ifdef DEBUGGING
				string symmkey_hex = hexify_str(symmkey, S_SYMMETRIC_KEY);
				LOG("\tSymmetric key: \t\t" << symmkey_hex);
#else
				LOG("\tSymmetric key: \t\tAquired");
#endif
			}
			LOG("");
		}
	}
	else {
		LOG("No available users.");
	}
}

ClientChoices Menu::get_choice(const string& myUsername)
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
				case 53:
					return ClientChoices::sendFile;
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

		bool ascii_ok = true;
		for (char c : username) {
			int i_c = (int)c;
			if (i_c < USERNAME_ALLOW_ASCII_START || i_c > USERNAME_ALLOW_ASCII_END) {
				LOG("Username must contain characters only from 32 in ascii to 127 in ascii.");
				ascii_ok = false;
				break;
			}
		}
		if (!ascii_ok)
			continue;

		if (username.size() >= 1 && username.size() <= S_USERNAME)
			return username;
		else
			LOG("Incorrect allowed username length.");
	}
}

string Menu::readText()
{
	LOG("Please type the message:");
	string line;
	getline(cin, line);

	return line;
}

std::string Menu::chooseFile()
{
	while (true) {
		LOG("Please type the file path:");
		string path;
		getline(cin, path);
		if (boost::filesystem::exists(path)) {
			return path;
		}
		else {
			LOG("File doesn't exist. Please type valid file path.");
		}
	}
}

const MessageU_User Menu::chooseUser(const vector<MessageU_User>* availableUsers)
{
	//Check saved clients vector
	if (availableUsers->size() == 0) {
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
				for (size_t i = 0; i < availableUsers->size(); i++) {
					if (user_number == (i + 1)) {
						const auto& x = availableUsers->at(i);

						DEBUG("You chose user number: " << user_number << " with username: " << x.getUsername());
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
			for (const auto& x : *availableUsers) {
				string username = x.getUsername();

				if (username == line) {
					DEBUG("You chose username: " << username);
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

					for (const auto& x : *availableUsers) {
						ClientId clientId;
						x.getClientId(clientId);

                        string client_id_str((char*)clientId, S_CLIENT_ID);
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

