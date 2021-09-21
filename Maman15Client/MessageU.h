#pragma once

#include "ProtocolDefenitions.h"
#include "MyUser.h"
#include "Menu.h"
#include "Client.h"

//TODO: When implimented send file, client version is 2!
//TODO: Else, when send file is not implimented, client version is 1!
#define CLIENT_VERSION 1

class MessageU
{
private:
	std::string ip, port;

	MyUser me;
	Menu menu;

public:
	MessageU(std::string ip, std::string port);

	//The main loop.
	void start();

	//Choices
	void registerChoice(Client& client);
	void getClientsChoice(Client& client);
	void getPublicKeyChoice(Client& client);
	void sendMessageChoice(Client& client);
	void sendReqSymmKeyChoice(Client& client);
	void sendFileChoice(Client& client);
	void pullMessagesChoice(Client& client);
	void sendSymmKeyChoice(Client& client);
};

