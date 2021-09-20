#pragma once
#include <iostream>
#include <string>
#include "ProtocolDefenitions.h"
#include <boost/algorithm/hex.hpp>
#include "MenuDefenitions.h"
#include <vector>
#include "Debug.h"
#include "Utils.h"

//using namespace std; //bad practice
//using namespace MessageUProtocol; //bad practice

class InteractiveMenu
{
public:
	static void show_menu(std::string myUsername, MessageUProtocol::ClientId* myClientId);
	static Menu::ClientChoices get_choice();
	static std::string readUsername();
	static void getClientId(MessageUProtocol::ClientId result, std::vector<MessageUProtocol::User>* possibleClients);
	static std::string resolveUsername(MessageUProtocol::ClientId clientId, std::vector<MessageUProtocol::User>* users);
	static std::string readText();
	static bool yesNoChoice(std::string prompt, bool yesIsDefaultChoice = true);
	static void show_users(std::vector<MessageUProtocol::User>* users);
};


struct EmptyClientsList : public std::exception {
	const char* what() const throw() {
		return "You must first get clients list from server (in order to map username, or user number, to client id).";
	}
};