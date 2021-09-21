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

string MessageU_User::getUsername() const
{
	return username;
}

void MessageU_User::setClientId(MessageUProtocol::ClientId& clientId)
{
	memcpy(client_id, clientId, S_CLIENT_ID);
}

void MessageU_User::setUsername(string& _username)
{
	memcpy(username, _username.c_str(), S_USERNAME);
}
