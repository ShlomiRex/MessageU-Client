#include "MessageU_User.h"

using namespace std;
using namespace MessageUProtocol;

MessageU_User::MessageU_User()
{
	memset(client_id, 0, S_CLIENT_ID);
	memset(username, 0, S_USERNAME);
	memset(privkey, 0, S_PRIVATE_KEY);
	memset(pubkey, 0, S_PUBLIC_KEY);
	memset(symmkey, 0, S_SYMMETRIC_KEY);
}

void MessageU_User::getClientId(ClientId& result) const
{
	memcpy(result, client_id, S_CLIENT_ID);
}

void MessageU_User::getPublicKey(MessageUProtocol::PublicKey& result) const
{
	memcpy(result, pubkey, S_PUBLIC_KEY);
}

void MessageU_User::getPrivateKey(MessageUProtocol::PrivateKey& result) const
{
	memcpy(result, privkey, S_PRIVATE_KEY);
}

void MessageU_User::getSymmetricKey(MessageUProtocol::SymmetricKey& result) const
{
	memcpy(result, symmkey, S_SYMMETRIC_KEY);
}

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

void MessageU_User::setClientId(const MessageUProtocol::ClientId& clientId)
{
	memcpy(client_id, clientId, S_CLIENT_ID);
}

void MessageU_User::setUsername(const Username& _username)
{
	memcpy(username, _username, S_USERNAME);
}

void MessageU_User::setPublicKey(const MessageUProtocol::PublicKey& other)
{
	memcpy(client_id, other, S_CLIENT_ID);
}

void MessageU_User::setPrivateKey(const MessageUProtocol::PrivateKey& other)
{
	memcpy(pubkey, other, S_PUBLIC_KEY); //Here, we still don't know the public ip of each client. But it's ok, we cna deal with it later.
}

void MessageU_User::setSymmKey(const MessageUProtocol::SymmetricKey& other)
{
	memcpy(symmkey, other, S_SYMMETRIC_KEY);
}
