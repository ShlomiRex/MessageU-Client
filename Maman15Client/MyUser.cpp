#include "MyUser.h"

using namespace std;
using namespace MessageUProtocol;

MyUser::MyUser()
{
	memset(client_id, 0, S_CLIENT_ID);
	memset(username, 0, S_USERNAME);
	memset(privkey, 0, S_PRIVATE_KEY);
	memset(pubkey, 0, S_PUBLIC_KEY);
	memset(symmkey, 0, S_SYMMETRIC_KEY);
}

void MyUser::getClientId(ClientId& result) const
{
	memcpy(result, client_id, S_CLIENT_ID);
}

void MyUser::getPublicKey(MessageUProtocol::PublicKey& result) const
{
	memcpy(result, pubkey, S_PUBLIC_KEY);
}

void MyUser::getPrivateKey(MessageUProtocol::PrivateKey& result) const
{
	memcpy(result, privkey, S_PRIVATE_KEY);
}

void MyUser::getSymmetricKey(MessageUProtocol::SymmetricKey& result) const
{
	memcpy(result, symmkey, S_SYMMETRIC_KEY);
}

string MyUser::getUsername() const
{
	return username;
}

void MyUser::setClientId(MessageUProtocol::ClientId& clientId)
{
	memcpy(client_id, clientId, S_CLIENT_ID);
}

void MyUser::setUsername(string& _username)
{
	memcpy(username, _username.c_str(), S_USERNAME);
}
