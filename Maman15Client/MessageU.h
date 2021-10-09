#pragma once

#include "ProtocolDefenitions.h"
#include "MessageU_User.h"
#include "Menu.h"
#include "Client.h"

#define CLIENT_VERSION 2

//Small class extension of MessageU_User
//MyUser can be registered or not
class MyUser : public MessageU_User {
private:
	bool registered = false;

public:
	bool isRegistered() {
		return registered;
	}
	void setRegistered() {
		registered = true;
	}
};

class MessageU
{
private:
	std::string ip, port;

	MyUser me;

	//Other clients
	std::vector<MessageU_User> users;

	//Find user by given client id. Returns index of the vector. If user not found, return -1.
	int findUser(const MessageUProtocol::ClientId& clientId) const;
	void readInfoFile();
public:
	MessageU(std::string ip, std::string port);

	//The main loop.
	void start();

	//Choices
	void registerChoice(Client& client);
	void getClientsChoice(Client& client);
	void getPublicKeyChoice(Client& client);
	void sendMessageChoice(Client& client);
	void sendReqSymmKeyChoice(Client& client);
	void sendFileChoice(Client& client);
	void pullMessagesChoice(Client& client);
	void sendSymmKeyChoice(Client& client);

	//Other
	void aquirePublicKey(Client& client, MessageU_User& destUser);
};

struct UserNotFound : public std::exception {
	const char* what() const throw() {
		return "Couldn't find user from users list.";
	}
};

struct EmptySymmKey : public std::exception {
	const char* what() const throw() {
		return "Symmetric key is empty. You need to get symmetric key.";
	}
};