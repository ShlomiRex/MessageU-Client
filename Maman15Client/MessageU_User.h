#pragma once

#include "ProtocolDefenitions.h"
#include <string>

class MessageU_User
{
private:
	MessageUProtocol::ClientId client_id;
	MessageUProtocol::PublicKey pubkey;
	std::string privkey; //Private key length is varied. 
	MessageUProtocol::SymmetricKey symmkey;
	std::string username;

public:
	MessageU_User();

	//Getters
	void getClientId(MessageUProtocol::ClientId& result) const;
	const std::string getUsername() const;
	void getPublicKey(MessageUProtocol::PublicKey& result) const;
	const std::string getPrivateKey() const;
	void getSymmetricKey(MessageUProtocol::SymmetricKey& result) const;

	//Setters
	void setClientId(const MessageUProtocol::ClientId& clientId);
	void setUsername(const std::string& other);
	void setPublicKey(const MessageUProtocol::PublicKey& other);
	void setPrivateKey(const std::string& other);
	void setSymmKey(const MessageUProtocol::SymmetricKey& other);
};
