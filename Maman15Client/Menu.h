#pragma once

#include "Debug.h"
#include "ProtocolDefenitions.h"
#include <vector>
#include <iostream>
#include <string>
#include <boost/algorithm/hex.hpp> //to read hex from input
#include "Utils.h"

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

typedef struct {
	MessageUProtocol::ClientId client_id;
	MessageUProtocol::Username username;
	MessageUProtocol::PublicKey publicKey;
} MenuUser;

class Menu
{
private:
	MessageUProtocol::User me;
	//We need write access, because of GetClients request. So we give friendship to 'updateUsers' function.
	std::vector<MenuUser> users;
	bool registered;

public:
	Menu();
	~Menu();

	//Gets
	std::string getUsername() const;
	void getMyClientId(MessageUProtocol::ClientId& result) const;
	bool isRegistered();
	const std::vector<MenuUser> getUsers();

	//Sets
	void setUsername(std::string& username);
	void setClientId(MessageUProtocol::ClientId& clientId);
	friend void updateUsers(Menu& menuobj, std::vector<MenuUser>* serverResponse);
	void setUserPublicKey(const MessageUProtocol::ClientId& userClientId, const MessageUProtocol::PublicKey& pubkey);
	void setRegistered();

	//Prints
	void show() const;
	void showUsers() const;

	//Read input
	ClientChoices get_choice() const;
	const MenuUser chooseUser() const;
	bool yesNoChoice(std::string prompt, bool yesIsDefaultChoice);

	//Special / logic
	void readAndSetMyUsername();
};

struct EmptyClientsList : public std::exception {
	const char* what() const throw() {
		return "You must first get clients list from server (in order to choose destination user).";
	}
};

struct MenuUserNotFound : public std::exception {
	const char* what() const throw() {
		return "Couldn't find user from users vector.";
	}
};