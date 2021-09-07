#include "Client.h"
#include "InteractiveMenu.h"
#include <boost/filesystem.hpp>

#define LOG(msg) cout << "[main] " << msg << endl;

namespace fs = boost::filesystem;
using namespace std;

int main()
{
	fs::ifstream server_info("server.info");
	char buff[1024] = { 0 };
	server_info.read(buff, 1024);
	string str_buff = buff;
	size_t index = str_buff.find(':');

	string ip = str_buff.substr(0, index);
	string port = str_buff.substr(index + 1);

	InteractiveMenu interactiveMenu;
	interactiveMenu.show_menu();
	ClientChoices choice = interactiveMenu.get_choice();

	//If using database, client version is 2!
	bool isUsingSQLDatabase = true; // TODO: Change?
	size_t clientVersion = (isUsingSQLDatabase == true) ? 2 : 1;
	Client client(ip, port, clientVersion);

	if (choice == ClientChoices::registerUser) {
		string username = interactiveMenu.getUsernameForRegister();
		client.registerUser(username);
	}
	else {
		LOG("Not yet implimented");
	}

	LOG("Finished running, exiting program");
}