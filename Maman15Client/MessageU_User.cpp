#include "MessageU_User.h"

using namespace std;
using namespace MessageUProtocol;

MessageU_User::MessageU_User()
{
	memset(client_id, 0, S_CLIENT_ID);
	memset(pubkey, 0, S_PUBLIC_KEY);
	memset(symmkey, 0, S_SYMMETRIC_KEY);
}

void MessageU_User::getClientId(ClientId& result) const
{
	memcpy(result, client_id, S_CLIENT_ID);
}

const std::string MessageU_User::getUsername() const
{
	return username;
}

void MessageU_User::getPublicKey(MessageUProtocol::PublicKey& result) const
{
	memcpy(result, pubkey, S_PUBLIC_KEY);
}

const string MessageU_User::getPrivateKey() const
{
	return privkey;
}

void MessageU_User::getSymmetricKey(MessageUProtocol::SymmetricKey& result) const
{
	memcpy(result, symmkey, S_SYMMETRIC_KEY);
}


/*
void MessageU_User::getUsername(Username& result) const
{
	memcpy(result, username, S_USERNAME);
}


const string MessageU_User::getUsernameStr() const
{
	Username username;
	getUsername(username);
	string username_str(username);
	return username_str;
}
*/

/*
const string MessageU_User::getPublicKey() const
{
	return publicKey;
}

const std::string MessageU_User::getPrivateKey() const
{
	return privateKey;
}

const std::string MessageU_User::getSymmKey() const
{
	return symmKey;
}
*/
void MessageU_User::setClientId(const MessageUProtocol::ClientId& clientId)
{
	memcpy(client_id, clientId, S_CLIENT_ID);
}

/*
void MessageU_User::setUsername(const Username& _username)
{
	memcpy(username, _username, S_USERNAME);
}
*/

void MessageU_User::setUsername(const std::string& other)
{
	username = other;
}

/*
void MessageU_User::setPublicKey(const string& other)
{
	publicKey = other;
}

void MessageU_User::setPrivateKey(const string& other)
{
	privateKey = other;
}

void MessageU_User::setSymmKey(const std::string& other)
{
	symmKey = other;
}
*/

void MessageU_User::setPublicKey(const MessageUProtocol::PublicKey& other)
{
	memcpy(pubkey, other, S_PUBLIC_KEY);
}


void MessageU_User::setPrivateKey(const string& other)
{
	privkey = other;
}


void MessageU_User::setSymmKey(const MessageUProtocol::SymmetricKey& other)
{
	memcpy(symmkey, other, S_SYMMETRIC_KEY);
}
