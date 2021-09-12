#pragma once
#include <iostream>
#include <string>
#include "OpCodes.h"
#include "ProtocolDefenitions.h"
#include <boost/algorithm/hex.hpp>
#include "MenuDefenitions.h"

using namespace std;

class InteractiveMenu
{
public:
	InteractiveMenu();
	void show_menu();
	ClientChoices get_choice();
	string getUsernameForRegister();
	void getClientId(ClientId buffer);
};

