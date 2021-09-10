#pragma once
#include <iostream>
#include <string>
#include "OpCodes.h"
#include "ProtocolDefenitions.h"

using namespace std;

class InteractiveMenu
{
public:
	InteractiveMenu();
	void show_menu();
	ClientChoices get_choice();
	string getUsernameForRegister();
};

