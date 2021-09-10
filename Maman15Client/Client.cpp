#include "Client.h"

using namespace std;

#define LOG(msg) cout << "[Client] " << msg << endl;

Client::Client(string ip, string port, uint8_t clientVersion) : request(clientVersion) {
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

	char clientId[S_CLIENT_ID] = { 0 };
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
	if (response == nullptr)
		return;

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
			if (s_payload != S_CLIENT_ID) {
				stringstream ss;
				ss << "Response ClientID size is not " << S_CLIENT_ID;
				ss << " bytes!";
				throw string(ss.str());
			}
			
			LOG("Registeration was a success! Client ID got from server:");
			hexify((const unsigned char*)clientId, S_CLIENT_ID);

			LOG("Writing username and client id to file: " << FILE_REGISTER);


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
	try {
		size_t bytes_recv = this->socket->receive(boost::asio::buffer(buffer, S_PACKET_SIZE));
		LOG("Received response (" << bytes_recv << " bytes): ");
		hexify((const unsigned char*)buffer, bytes_recv);

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
	//TODO: Get client id from me.info ?
	request.pack_clientId(clientId);
}