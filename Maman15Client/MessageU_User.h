#pragma once

#include "ProtocolDefenitions.h"
#include <string>

class MessageU_User
{
private:
	MessageUProtocol::ClientId client_id;
	MessageUProtocol::Username username;
	MessageUProtocol::PublicKey pubkey;
	MessageUProtocol::PrivateKey privkey;
	MessageUProtocol::SymmetricKey symmkey;
public:
	MessageU_User();

	//Getters
	void getClientId(MessageUProtocol::ClientId& result) const;
	void getUsername(MessageUProtocol::Username& result) const;
	const std::string getUsernameStr() const;
	void getPublicKey(MessageUProtocol::PublicKey& result) const;
	void getPrivateKey(MessageUProtocol::PrivateKey& result) const;
	void getSymmetricKey(MessageUProtocol::SymmetricKey& result) const;

	//Setters
	void setClientId(const MessageUProtocol::ClientId& clientId);
	void setUsername(const MessageUProtocol::Username& _username);
	void setPublicKey(const MessageUProtocol::PublicKey& other);
	void setPrivateKey(const MessageUProtocol::PrivateKey& other);
	void setSymmKey(const MessageUProtocol::SymmetricKey& other);

};
