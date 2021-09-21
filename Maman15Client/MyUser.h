#pragma once

#include "ProtocolDefenitions.h"
#include <string>

class MyUser
{
private:
	bool registered = false;

	MessageUProtocol::ClientId client_id;
	MessageUProtocol::Username username;
	MessageUProtocol::PublicKey pubkey;
	MessageUProtocol::PrivateKey privkey;
	MessageUProtocol::SymmetricKey symmkey;
public:
	MyUser();

	//Getters
	void getClientId(MessageUProtocol::ClientId& result) const;
	std::string getUsername() const;
	void getPublicKey(MessageUProtocol::PublicKey& result) const;
	void getPrivateKey(MessageUProtocol::PrivateKey& result) const;
	void getSymmetricKey(MessageUProtocol::SymmetricKey& result) const;

	//Setters
	void setClientId(MessageUProtocol::ClientId& clientId);
	void setUsername(std::string& _username);

};

