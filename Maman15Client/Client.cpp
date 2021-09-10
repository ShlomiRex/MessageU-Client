#include "Client.h"

using namespace std;

#define LOG(msg) cout << "[Client] " << msg << endl;

Client::Client(string ip, string port, size_t clientVersion) : request(clientVersion) {
	//Initialize all internal fields and connect to server.

	try {
		this->io_context = new boost::asio::io_context();
		this->socket = new boost::asio::ip::tcp::socket(*io_context);
		this->resolver = new boost::asio::ip::tcp::resolver(*io_context);
		this->endpoints = new boost::asio::ip::tcp::resolver::results_type();

		*this->endpoints = resolver->resolve(ip, port);
		LOG("Connecting to server...");
		boost::asio::connect(*socket, *endpoints);
		LOG("Connected");
	}
	catch (std::exception& e)
	{
		LOG(e.what());
	}
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

	char clientId[16] = { 0 };
	request.pack_clientId(clientId);
	request.pack_version();
	request.pack_code(RequestCodes::registerUser);

	//Payload size: name (with null terminator) + public key
	request.pack_payloadSize(username.size() + 1 + RSAPublicWrapper::KEYSIZE);

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

	//Parse response
	try {
		uint16_t code = response->getCode();
		ResponseCodes _code = static_cast<ResponseCodes>(code);

		if (_code == ResponseCodes::error) {
			LOG("Received ERROR response!");
			LOG("Username '" << username << "' is already in the database!");
		}
		else if (_code == ResponseCodes::registerSuccess) {
			size_t s_payload = response->getPayloadSize();
			const char* clientId = response->getPayload();
			if (s_payload != 16) {
				throw exception("Response ClientID size is not 16 bytes!");
			}
			
			LOG("Registeration was a success! Client ID got from server:");
			hexify((const unsigned char*)clientId, 16);

			LOG("Writing username and client id to file: " << FILE_REGISTER);
			//Write regular string (first line)
			ofstream file(FILE_REGISTER);
			file << username << endl;
			file.flush();
			file.close();
			//In the second line, write in binary the client id.
			file.open(FILE_REGISTER, ios::app | ios::binary);
			file.write(clientId, 16);
			file.close();
			LOG("Done writing");
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

	LOG("Sending request (" << packetSize << " bytes): ");
	hexify((const unsigned char*)buff, packetSize);

	size_t bytesSent = this->socket->send(boost::asio::buffer(buff, packetSize));
	LOG("Sent " << bytesSent << " bytes!");
	return bytesSent;
}

Response* Client::recvResponse() {
	char buffer[S_PACKET_SIZE] = { 0 };
	LOG("Receving response...");
	size_t bytes_recv = this->socket->receive(boost::asio::buffer(buffer, S_PACKET_SIZE));
	LOG("Received response (" << bytes_recv << " bytes): ");
	hexify((const unsigned char*)buffer, bytes_recv);

	Response* response = new Response(buffer, bytes_recv);
	return response;
}

void Client::getClients() {
	//TODO: Complete
}