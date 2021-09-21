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

typedef struct MenuUser {
	MessageUProtocol::ClientId client_id;
	MessageUProtocol::Username username;
	MessageUProtocol::PublicKey publicKey;
	MessageUProtocol::SymmetricKey symmKey;

	MenuUser() {
		memset(client_id, 0, S_CLIENT_ID);
		memset(username, 0, S_USERNAME);
		memset(publicKey, 0, S_PUBLIC_KEY);
		memset(symmKey, 0, S_SYMMETRIC_KEY);
	}
} MenuUser;

class Menu
{
private:
	//We need write access, because of GetClients request. So we give friendship to 'updateUsers' function.
	std::vector<MenuUser> users;
	bool registered;

public:
	Menu();

	//Gets
	bool isRegistered();
	const std::vector<MenuUser> getUsers();

	//Sets
	friend void updateUsers(Menu& menuobj, std::vector<MenuUser>* serverResponse);
	void setUserPublicKey(const MessageUProtocol::ClientId& userClientId, const MessageUProtocol::PublicKey& pubkey);
	void setUserSymmKey(const MessageUProtocol::ClientId& userClientId, const MessageUProtocol::SymmetricKey& symmkey);
	void setRegistered();

	//Prints
	void show(const std::string& myUsername) const;
	void showUsers() const;

	//Read input
	ClientChoices get_choice(const std::string& myUsername) const;
	const MenuUser chooseUser() const;
	bool yesNoChoice(std::string prompt, bool yesIsDefaultChoice);
	std::string readUsername();
};

struct EmptyClientsList : public std::exception {
	const char* what() const throw() {
		return "You must first get clients list from server (in order to choose destination user, or to map users and client ids).";
	}
};

struct MenuUserNotFound : public std::exception {
	const char* what() const throw() {
		return "Couldn't find user from users vector.";
	}
};

struct NotRegistered : public std::exception {
	const char* what() const throw() {
		return "You must register first.";
	}
};

struct EmptyPublicKey : public std::exception {
private:
	MenuUser destUser;
	std::string mystr;
public:
	EmptyPublicKey(MenuUser& destUser) : destUser(destUser) {
		std::stringstream ss;
		ss << "You need to get " << destUser.username << "'s public key.";

		mystr = ss.str();
	}
	const char* what() const throw() {
		return mystr.c_str();
	}

	MenuUser getDestUser() {
		return destUser;
	}
};