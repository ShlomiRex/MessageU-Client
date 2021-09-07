#include "Client.h"

using namespace std;
using boost::asio::ip::tcp;

#define LOG(msg) cout << "[Client] " << msg << endl;

Client::Client(string ip, string port, size_t clientVersion) {

	//boost::asio::ip::tcp::socket* socket;
	//boost::asio::ip::tcp::resolver* resolver;
	//boost::asio::ip::tcp::resolver::results_type* endpoints;
	this->clientVersion = clientVersion;
	try {
		this->io_context = new boost::asio::io_context();
		this->socket = new boost::asio::ip::tcp::socket(*io_context);
		this->resolver = new tcp::resolver(*io_context);
		this->endpoints = new boost::asio::ip::tcp::resolver::results_type();

		*this->endpoints = resolver->resolve(ip, port);
		//tcp::resolver::results_type endpoints = resolver.resolve(ip, port);
		//tcp::socket socket(this->io_context);
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
}

void Client::registerUser(string user) {
	LOG("Registering user...");
	RequestCodes reqCode = RequestCodes::registerUser;
	//TODO: Public key


}