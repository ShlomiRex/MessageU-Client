#include "Client.h"
#include "Debug.h"
#include "ProtocolDefenitions.h"
#include "Menu.h"
#include "MessageU_User.h"
#include "MessageU.h"

#define DEBUG_PREFIX "[main] "

int main()
{
	std::string ip, port;
	FileManager::readServer(ip, port);

	MessageU messageU(ip, port);
	messageU.start(); //loops
	LOG("Finished running, exiting program");
}
