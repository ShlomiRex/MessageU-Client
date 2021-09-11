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



Client::Client(string ip, string port, uint8_t clientVersion) : request(clientVersion) {
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

	char clientId[S_CLIENT_ID] = { 0 };
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
	Response* response = recvResponse();
	if (response == nullptr)
		return;

	//Parse response
	try {
		uint16_t code = response->getCode();
		ResponseCodes _code = static_cast<ResponseCodes>(code);

		if (_code == ResponseCodes::error) {
			LOG("Received ERROR response!");
			LOG("Try again, or try diffirent username.");
		}
		else if (_code == ResponseCodes::registerSuccess) {
			size_t s_payload = response->getPayloadSize();
			const char* clientId = response->getPayload();
			if (s_payload != S_CLIENT_ID) {
				stringstream ss;
				ss << "Response ClientID size is not " << S_CLIENT_ID;
				ss << " bytes!";
				throw string(ss.str());
			}
			
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
		else {
			string e = "Response code: " + code;
			e += " is not recognized(invalid).";
			throw string(e);
		}
	}
	catch (exception& e) {
		LOG("ERROR while parsing response: " << e.what());
	}

	if (response != nullptr)
		delete response;
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

Response* Client::recvResponse(bool with_payload) {
	char buffer[S_PACKET_SIZE] = { 0 };
	DEBUG("Receving response...");
	try {
		size_t bytestoRecv = S_PACKET_SIZE;
		if (! with_payload)
			bytestoRecv = S_RESPONSE_HEADER;
		size_t bytes_recv = this->socket->receive(boost::asio::buffer(buffer, bytestoRecv));
		DEBUG("Received response (" << bytes_recv << " bytes): ");
#ifdef DEBUGGING
		hexify((const unsigned char*)buffer, bytes_recv);
#endif
		Response* response = new Response(buffer, bytes_recv);
		return response;
	}
	catch (exception& e) {
		LOG("Error: " << e.what());
		LOG("Is the server down?");
		return 0;
	}
}

void Client::getClients() {
	LOG("Getting clients...");

	char clientId[S_CLIENT_ID] = { 0 };
	FileManager::getSavedClientId(clientId);
	request.pack_clientId(clientId);
	request.pack_version();
	request.pack_code(RequestCodes::reqClientList);
	request.pack_payloadSize(0);

	sendRequest();

	//Get only the header, for now (by giving 'false' flag)
	Response* response = recvResponse(false);
	if (response == nullptr)
		return;

	//Parse response
	try {
		uint16_t code = response->getCode();
		ResponseCodes _code = static_cast<ResponseCodes>(code);

		if (_code == ResponseCodes::error) {
			LOG("Received ERROR response!");
		}
		else if (_code == ResponseCodes::listUsers) {
			LOG("Get clients response is success!");
			size_t s_payload = response->getPayloadSize();

			//We need to read s_payload
			size_t payloadBytesRead = 0;
			size_t s_users = 0;
			cout << endl;
			while (payloadBytesRead < s_payload) {
				s_users += 1;

				//Receive next payload
				char buffer[S_CLIENT_ID + S_USERNAME] = { 0 };
				size_t bytes_recv = this->socket->receive(boost::asio::buffer(buffer, S_CLIENT_ID + S_USERNAME));
				DEBUG("Read " << bytes_recv << " bytes from payload.");
				payloadBytesRead += bytes_recv;

				//Read to buffers
				BufferReader reader(buffer, S_CLIENT_ID + S_USERNAME);
				char client_id[S_CLIENT_ID] = { 0 };
				char username[S_USERNAME] = { 0 };
				reader.read(S_CLIENT_ID, client_id, S_CLIENT_ID);
				reader.read(S_USERNAME, username, S_USERNAME);

				//Print buffers
				LOG("User " << s_users << ": " << username);
				LOG("Client ID:");
				hexify((const unsigned char*)client_id, S_CLIENT_ID);
				cout << endl;
			}
			LOG("Done listing " << s_users << " users.");
		}
		else {
			string e = "Response code: " + code;
			e += " is not recognized(invalid).";
			throw string(e);
		}
	}
	catch (exception& e) {
		LOG("Error: " << e.what());
	}
}

void Client::getPublicKey(char client_id[S_CLIENT_ID], char result_pub_key[S_PUBLIC_KEY]) {
	LOG("Getting public key...");


}

