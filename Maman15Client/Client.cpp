#include "Client.h"

using namespace std;
using boost::asio::ip::tcp;

#define LOG(msg) cout << "[Client] " << msg << endl;

Client::Client(string ip, string port, size_t clientVersion) {
	//Initialize all internal fields and connect to server.

	this->clientVersion = clientVersion;
	this->reqPacket = new char[S_PACKET_SIZE];
	this->reqWriter = new BufferWriter(this->reqPacket, S_PACKET_SIZE);

	try {
		this->io_context = new boost::asio::io_context();
		this->socket = new boost::asio::ip::tcp::socket(*io_context);
		this->resolver = new tcp::resolver(*io_context);
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


	sendRequest();

	
	char data[S_PACKET_SIZE] = { 0 };
	size_t bytesRead = recvResponse(data);

	try {
		Response response(data, bytesRead);
		uint16_t code = response.getCode();
		ResponseCodes _code = static_cast<ResponseCodes>(code);

		if (_code == ResponseCodes::error) {
			LOG("Received ERROR response!");
			LOG("User " << username << " is already in the database!");
		}
		else if (_code == ResponseCodes::registerSuccess) {
			LOG("Registeration was a success!");
		}
		else {
			LOG("Response code: " << code << " is not recognized.");
		}
	}
	catch (exception& e) {
		LOG("ERROR While parsing response: " << e.what());
		return;
	}
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

size_t Client::recvResponse(char* buffer) {
	LOG("Receving response...");
	size_t bytes_recv = this->socket->receive(boost::asio::buffer(buffer, S_PACKET_SIZE));
	LOG("Received response (" << bytes_recv << " bytes): ");
	hexify((const unsigned char*)buffer, bytes_recv);
	return bytes_recv;
}

