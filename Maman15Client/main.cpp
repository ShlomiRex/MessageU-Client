#include "main.h"

#define DEBUG_PREFIX "[main] "

int main()
{
	std::string ip, port;
	FileManager::readServer(ip, port);

	MessageU messageU(ip, port);
	messageU.start(); //loops
	LOG("Finished running, exiting program");
}
