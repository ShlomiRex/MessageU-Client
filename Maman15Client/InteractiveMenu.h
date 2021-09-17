#pragma once
#include <iostream>
#include <string>
#include "ProtocolDefenitions.h"
#include <boost/algorithm/hex.hpp>
#include "MenuDefenitions.h"
#include <vector>
#include "Debug.h"

using namespace std;

class InteractiveMenu
{
public:
	static void show_menu();
	static Menu::ClientChoices get_choice();
	static string readUsername();
	static void getClientId(ClientId result, vector<User>* possibleClients);
	static string readText();
};


struct EmptyClientsList : public exception {

};