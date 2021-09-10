#include "Client.h"

using namespace std;

#define LOG(msg) cout << "[Client] " << msg << endl;

Client::Client(string ip, string port, size_t clientVersion) {
	//Initialize all internal fields and connect to server.

	this->clientVersion = clientVersion;
	this->reqPacket = new char[S_PACKET_SIZE];
	this->reqWriter = new BufferWriter(this->reqPacket, S_PACKET_SIZE);

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
		//std::cerr << e.what() << std::endl;
		LOG(e.what());
	}
}

Client::~Client() {
	delete io_context;
	delete socket;
	delete resolver;
	delete endpoints;

	delete[] reqPacket;
	delete reqWriter;
}

void hexify(const unsigned char* buffer, unsigned int length)
{
	std::ios::fmtflags f(std::cout.flags());
	std::cout << std::hex;
	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	std::cout << std::endl;
	std::cout.flags(f);
}

void Client::registerUser(string username) {
	LOG("Registering user...");

	//Check if the info file exists
	if (boost::filesystem::exists(REG_FILE_INFO)) {
		LOG(REG_FILE_INFO << " already exists! Will not register.");
		return;
	}

	char clientId[16] = { 0 };
	pack_clientId(clientId);
	pack_version();
	pack_code(RequestCodes::registerUser);

	//Payload size: name (with null terminator) + public key
	pack_payloadSize(username.size() + 1 + RSAPublicWrapper::KEYSIZE);

	//Payload: Name
	LOG("Packing name (" << username.size() + 1 << " bytes, with null terminator): " << username);
	this->reqWriter->write(username.c_str(), username.size());
	this->reqWriter->write1byte(0); //With null terminator

	//Payload: Public key
	RSAPrivateWrapper rsapriv;
	char pubkeybuff[RSAPublicWrapper::KEYSIZE];
	rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);
	LOG("Packing public key (" << RSAPublicWrapper::KEYSIZE << " bytes): ");
	hexify((const unsigned char*)pubkeybuff, RSAPublicWrapper::KEYSIZE);
	this->reqWriter->write(pubkeybuff, RSAPublicWrapper::KEYSIZE);

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

			LOG("Writing username and client id to file: " << REG_FILE_INFO);
			//Write regular string (first line)
			ofstream file(REG_FILE_INFO);
			file << username << endl;
			file.flush();
			file.close();
			//In the second line, write in binary the client id.
			file.open(REG_FILE_INFO, ios::app | ios::binary);
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

void Client::pack_clientId(const char clientId[16]) {
	LOG("Packing clientId (16 bytes):");
	hexify((const unsigned char*)clientId, 16);

	this->reqWriter->write(clientId, 16);
}

void Client::pack_version() {
	LOG("Packing version (1 byte): " << this->clientVersion);
	this->reqWriter->write1byte(this->clientVersion);
}

void Client::pack_code(RequestCodes code) {
	uint16_t reqCode = static_cast<uint16_t>(code);

	LOG("Packing code (2 bytes): " << reqCode);
	this->reqWriter->write2bytes(reqCode);
}

void Client::pack_payloadSize(uint32_t size) {
	LOG("Packing payload size (4 bytes): " << size);
	this->reqWriter->write4bytes(size);
}

size_t Client::sendRequest() {
	size_t packetSize = this->reqWriter->getOffset();
	char* buff = this->reqPacket;

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