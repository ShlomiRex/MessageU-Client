#pragma once
#include <iostream>
#include <string>
#include "OpCodes.h"
#include "ProtocolDefenitions.h"
#include <boost/algorithm/hex.hpp>

using namespace std;

class InteractiveMenu
{
public:
	InteractiveMenu();
	void show_menu();
	ClientChoices get_choice();
	string getUsernameForRegister();
	void getClientId(char buffer[S_CLIENT_ID]);
};

