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
	getSavedClientId(clientId);
	request.pack_clientId(clientId);
	request.pack_version();
	request.pack_code(RequestCodes::reqClientList);
	request.pack_payloadSize(0);

	sendRequest();

	Response* response = recvResponse();
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
			LOG("Get clients success response!");
			size_t s_payload = response->getPayloadSize();
			const char* payload = response->getPayload();


		}
		else {
			string e = "Response code: " + code;
			e += " is not recognized(invalid).";
			throw string(e);
		}
	}
	catch (exception& e) {

	}
}

string Client::getSavedUsername() {
	ifstream file(FILE_REGISTER);

	string line1;
	getline(file, line1);

	return line1;
}

const char* Client::getSavedPrivateKey() {
	ifstream file(FILE_REGISTER);

	string line1, line2;
	getline(file, line1);
	getline(file, line2);

	char* private_key = new char[S_FILE_REGISTER];
	private_key = { 0 };

	file.read(private_key, S_FILE_REGISTER);

	return private_key;
}

void Client::getSavedClientId(char buffer[S_CLIENT_ID]) {
	ifstream file(FILE_REGISTER);

	string line1, line2;
	getline(file, line1);
	getline(file, line2);

	// Remove spaces
	auto noSpaceEnd = std::remove(line2.begin(), line2.end(), ' ');
	line2.erase(noSpaceEnd, line2.end());

	//std::remove_if(line2.begin(), line2.end(), isspace);

	//boost::algorithm::erase_all(line2, ' ');

	//string hash = boost::algorithm::unhex(string("313233343536373839"));
	//string hash2 = boost::algorithm::unhex(string("31 32 33 34 35 36 37 38 39"));

	string hash = boost::algorithm::unhex(line2);
	if (hash.size() != S_CLIENT_ID) {
		throw exception("Couldn't properly read client id from the file. (Hex size is not 16)");
	}

	for (int i = 0; i < S_CLIENT_ID; i++) {
		buffer[i] = hash.at(i);
	}
}