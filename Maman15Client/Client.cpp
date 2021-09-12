#include "Client.h"

using namespace std;

//#define DEBUGGING
#ifdef DEBUGGING
	#define DEBUG(msg) cout << "[Debug] [Client] " << msg << endl;
#endif // DEBUG
#ifndef DEBUGGING
	#define DEBUG(msg) 
#endif

#define LOG(msg) cout << "[Client] " << msg << endl;

Client::Client(string ip, string port, Version clientVersion) : request(clientVersion) {
	//Initialize all internal fields and connect to server.

	this->io_context = new boost::asio::io_context();
	this->socket = new boost::asio::ip::tcp::socket(*io_context);
	this->resolver = new boost::asio::ip::tcp::resolver(*io_context);
	this->endpoints = new boost::asio::ip::tcp::resolver::results_type();

	*this->endpoints = resolver->resolve(ip, port);
	LOG("Connecting to server...");
	boost::asio::connect(*socket, *endpoints);
}

Client::~Client() {
	delete io_context;
	delete socket;
	delete resolver;
	delete endpoints;
}

void Client::registerUser(string username) {
	LOG("Registering user...");

	//Check if the info file exists
	if (boost::filesystem::exists(FILE_REGISTER)) {
		LOG(FILE_REGISTER << " already exists! Will not register.");
		return;
	}

	ClientId clientId = { 0 };
	request.pack_clientId(clientId);
	request.pack_version();
	request.pack_code(RequestCodes::registerUser);

	//Payload size: name (with null terminator) + public key
	request.pack_payloadSize(255 + RSAPublicWrapper::KEYSIZE);

	//Payload: Name
	request.pack_username(username);

	//Payload: Public key
	RSAPrivateWrapper rsapriv;
	char pubkeybuff[RSAPublicWrapper::KEYSIZE];
	rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);
	request.pack_pub_key(pubkeybuff);

	//Send request
	sendRequest();

	//Get response
	try {
		ResponseHeader header = recvResponseHeader(ResponseCodes::registerSuccess);

		//const char* clientId = recvNextPayload(header.getPayloadSize());

		ClientId clientId;
		recvClientId(clientId);

		LOG("Registeration was a success! Client ID got from server:");
		hexify((const unsigned char*)clientId, S_CLIENT_ID);

		DEBUG("Writing username and client id to file: " << FILE_REGISTER);

		//In the first line, write username
		ofstream file(FILE_REGISTER);
		file << username << endl;
		file.flush();
		file.close();

		//In the second line, write the client id in human readable space seperated hex.
		file.open(FILE_REGISTER, ios::app);
		string str_clientid = hexify_str(clientId, S_CLIENT_ID);
		file.write(str_clientid.c_str(), str_clientid.size());
		file.write("\n", 1);

		//In the third line, write private key
		string private_key = rsapriv.getPrivateKey();
		string base64_private_key = Base64Wrapper::encode(private_key);
		file.write(base64_private_key.c_str(), base64_private_key.size());

		file.close();
		DEBUG("Done writing");
	}
	catch (exception& e) {
		LOG(e.what());
	}
}

size_t Client::sendRequest() {
	size_t packetSize = request.getPacketSize();
	const char* buff = request.getPacket();

	DEBUG("Sending request (" << packetSize << " bytes): ");
#ifdef DEBUGGING
	hexify((const unsigned char*)buff, packetSize);
#endif
	size_t bytesSent = this->socket->send(boost::asio::buffer(buff, packetSize));
	DEBUG("Sent " << bytesSent << " bytes!");
	return bytesSent;
}

ResponseHeader Client::recvResponseHeader(ResponseCodes requiredCode) {
	DEBUG("Receving response header...");

	const char* payload = recvNextPayload(S_RESPONSE_HEADER);

#ifdef DEBUGGING
	hexify((const unsigned char*)payload, S_RESPONSE_HEADER);
#endif
	ResponseHeader header(payload, S_RESPONSE_HEADER);

	//Parse code
	ResponseCodes _code = static_cast<ResponseCodes>(header.getCode());
	if (_code == ResponseCodes::error) {
		LOG("Received ERROR response!");
		throw ResponseErrorException();
	}
	else if (_code != requiredCode) {
		throw InvalidResponseCodeException();
	}

	return header;
}

void Client::getClients() {
	LOG("Getting clients...");

	ClientId clientId = { 0 };
	try {
		FileManager::getSavedClientId(clientId);
	}
	catch (exception& e) {
		LOG(e.what());
		LOG("Error while getting client id from " << FILE_REGISTER);
		return;
	}
	
	request.pack_clientId(clientId);
	request.pack_version();
	request.pack_code(RequestCodes::reqClientList);
	request.pack_payloadSize(0);

	sendRequest();

	//Get response
	
	try {
		//Get only the header, for now
		ResponseHeader header = recvResponseHeader(ResponseCodes::listUsers);

		LOG("Get clients response is success!");

		//We need to read s_payload
		size_t payloadBytesRead = 0;
		size_t s_users = 0;
		cout << endl;
		while (payloadBytesRead < header.getPayloadSize()) {
			s_users += 1;

			Response_UsetList user = recvNextUserInList();
			payloadBytesRead += sizeof(user);

			LOG("User " << s_users << ": " << user.username);
			LOG("Client ID:");
			hexify((const unsigned char*)user.client_id, S_CLIENT_ID);
			cout << endl;
		}
		LOG("Done listing " << s_users << " users.");
	}
	catch (exception& e) {
		LOG(e.what());
	}

}

void Client::getPublicKey(ClientId client_id, PublicKey result_pub_key) {
	LOG("Getting public key...");

	//First, get my own client id
	ClientId my_client_id = { 0 };
	FileManager::getSavedClientId(my_client_id);

	//Pack header
	request.pack_clientId(my_client_id);
	request.pack_version();
	request.pack_code(RequestCodes::reqPublicKey);
	request.pack_payloadSize(S_CLIENT_ID);
	
	//Pack payload
	request.pack_clientId(client_id);

	sendRequest();

	//Get response
	try {
		ResponseHeader header = recvResponseHeader(ResponseCodes::publicKey);

		ClientId clientId = { 0 };
		PublicKey pubKey = { 0 };
		recvClientId(clientId);
		recvPublicKey(pubKey);

		LOG("Public key (" << S_PUBLIC_KEY << " bytes): ");
		hexify((const unsigned char*)pubKey, S_PUBLIC_KEY);
	}
	catch (exception& e) {
		LOG(e.what());
	}
	
}

const char* Client::recvNextPayload(uint32_t amountRecvBytes) {
	DEBUG("Receving payload...");
	char* buffer = new char[amountRecvBytes];
	memset(buffer, 0, amountRecvBytes);

	size_t bytes_recv = this->socket->receive(boost::asio::buffer(buffer, amountRecvBytes));
	DEBUG("Received payload (" << bytes_recv << " bytes): ");
#ifdef DEBUGGING
	hexify((const unsigned char*)buffer, bytes_recv);
#endif

	if (bytes_recv != amountRecvBytes) {
		LOG("ERROR: Requested to receive " << amountRecvBytes << " bytes, but got only " << bytes_recv << " bytes!");
	}

	return buffer;
}

Response_UsetList Client::recvNextUserInList() {
	Response_UsetList result;

	this->recvClientId(result.client_id);
	this->recvUsername(result.username);

	return result;
}

void Client::recvClientId(ClientId result) {
	const char* clientId = recvNextPayload(S_CLIENT_ID);
	memcpy(result, clientId, S_CLIENT_ID);
	delete[] clientId;
}

void Client::recvUsername(Username result) {
	const char* clientId = recvNextPayload(S_USERNAME);
	memcpy(result, clientId, S_USERNAME);
	delete[] clientId;
}

void Client::recvPublicKey(PublicKey result) {
	const char* clientId = recvNextPayload(S_PUBLIC_KEY);
	memcpy(result, clientId, S_PUBLIC_KEY);
	delete[] clientId;
}
