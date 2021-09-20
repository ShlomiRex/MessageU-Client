#pragma once

#include "Debug.h"
#include "ProtocolDefenitions.h"
#include <vector>
#include <iostream>
#include <string>

enum class ClientChoices {
	registerUser = 10,
	reqClientList = 20,
	reqPublicKey = 30,
	reqPullWaitingMessages = 40,
	sendMessage = 50,
	sendReqSymmetricKey = 51,
	sendSymmetricKey = 52,
	sendFile = 53,
	exitProgram = 0
};

class Menu
{
private:
	MessageUProtocol::User me;
	//We need write access, because of GetClients request. So we give friendship to 'updateUsers' function.
	std::vector<MessageUProtocol::User> users;

public:
	Menu();
	~Menu();

	std::string getUsername();
	void getClientId(MessageUProtocol::ClientId result);

	void setUsername(std::string& username);
	void setClientId(MessageUProtocol::ClientId& clientId);
	friend void updateUsers(Menu& menuobj, std::vector<MessageUProtocol::User>* serverResponse);

	void show();
	ClientChoices get_choice();
	void readAndSetMyUsername();
};

