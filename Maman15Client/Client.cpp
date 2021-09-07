#include "Client.h"

using namespace std;
using boost::asio::ip::tcp;

#define LOG(msg) cout << "[Client] " << msg << endl;

Client::Client(string ip, string port, size_t clientVersion) {
	//Initialize all internal fields and connect to server.

	this->clientVersion = clientVersion;
	this->reqPacket = new char[S_PACKET_SIZE];
	this->reqWriter = new BufferWriter(this->reqPacket, S_PACKET_SIZE);
	//this->request = { 0 };

	try {
		this->io_context = new boost::asio::io_context();
		this->socket = new boost::asio::ip::tcp::socket(*io_context);
		this->resolver = new tcp::resolver(*io_context);
		this->endpoints = new boost::asio::ip::tcp::resolver::results_type();

		*this->endpoints = resolver->resolve(ip, port);
		LOG("Connecting to server...");
		boost::asio::connect(*socket, *endpoints);
		LOG("Connected");
		/*
		for (;;)
		{
			boost::array<char, 128> buf;
			boost::system::error_code error;

			size_t len = socket->read_some(boost::asio::buffer(buf), error);
			if (error == boost::asio::error::eof)
				break; // Connection closed cleanly by peer.
			else if (error)
				throw boost::system::system_error(error); // Some other error.

			std::cout.write(buf.data(), len);

		}
		*/
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
	this->reqWriter->write(username.c_str(), username.size());
	this->reqWriter->write1byte(0); //With null terminator

	//Payload: Public key
	RSAPrivateWrapper rsapriv;
	char pubkeybuff[RSAPublicWrapper::KEYSIZE];
	rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);
	LOG("Public key: ");
	hexify((const unsigned char*)pubkeybuff, 100);
	this->reqWriter->write(pubkeybuff, RSAPublicWrapper::KEYSIZE);


	sendRequest();
}

void Client::pack_clientId(const char clientId[16]) {
	this->reqWriter->write(clientId, 16);
}

void Client::pack_version() {
	this->reqWriter->write1byte(this->clientVersion);
}

void Client::pack_code(RequestCodes code) {
	uint16_t reqCode = static_cast<uint16_t>(code);
	this->reqWriter->write2bytes(reqCode);
}

void Client::pack_payloadSize(uint32_t size) {
	this->reqWriter->write4bytes(size);
}


size_t Client::sendRequest() {
	size_t bytesSent = boost::asio::write(*this->socket, boost::asio::buffer(this->reqPacket, this->reqWriter->getOffset()));
	return bytesSent;
}