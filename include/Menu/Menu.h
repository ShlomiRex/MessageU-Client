#pragma once

#include "Utils/Debug.h"
#include "ProtocolDefenitions.h"
#include <vector>
#include <iostream>
#include <string>
#include <boost/algorithm/hex.hpp> //to read hex from input
#include "Utils/Utils.h"
#include "MessageU/MessageU_User.h"
#include "Utils/BufferUtils.h"
#include <boost/filesystem.hpp>

#define SHOW_PUBKEY_MAX_CHARACTERS		16U
#define USERNAME_ALLOW_ASCII_START		32U
#define USERNAME_ALLOW_ASCII_END		127U

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
public:
	//Prints

	static void show(const std::string& myUsername);
	static void showUsers(const std::vector<MessageU_User>* availableUsers);

	//Read input

	static ClientChoices get_choice(const std::string& myUsername);
	static const MessageU_User chooseUser(const std::vector<MessageU_User>* availableUsers);
	static bool yesNoChoice(std::string prompt, bool yesIsDefaultChoice);
	static std::string readUsername();
	static std::string readText();
	static std::string chooseFile();
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
	MessageU_User destUser;
	std::string mystr;
public:
	EmptyPublicKey(MessageU_User& destUser) : destUser(destUser) {
		std::stringstream ss;
		ss << "You need to get " << destUser.getUsername() << "'s public key.";

		mystr = ss.str();
	}
	const char* what() const throw() {
		return mystr.c_str();
	}

	MessageU_User getDestUser() {
		return destUser;
	}
};