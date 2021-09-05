#include "Client.h"

using namespace std;
using boost::asio::ip::tcp;

#define LOG(msg) cout << msg << endl;

Client::Client(string ip, string port) : io_context() {
	try {
		tcp::resolver resolver(this->io_context);
		tcp::resolver::results_type endpoints = resolver.resolve(ip, port);
		tcp::socket socket(this->io_context);
		boost::asio::connect(socket, endpoints);
		for (;;)
		{
			boost::array<char, 128> buf;
			boost::system::error_code error;

			size_t len = socket.read_some(boost::asio::buffer(buf), error);
			if (error == boost::asio::error::eof)
				break; // Connection closed cleanly by peer.
			else if (error)
				throw boost::system::system_error(error); // Some other error.

			std::cout.write(buf.data(), len);

		}
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}


}