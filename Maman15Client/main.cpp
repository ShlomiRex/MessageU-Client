#include "Client.h"
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
using namespace std;

int main()
{
	fs::ifstream server_info("server.info");
	char buff[1024] = { 0 };
	server_info.read(buff, 1024);
	string str_buff = buff;
	size_t index = str_buff.find(':');

	string ip = str_buff.substr(0, index);
	string port = str_buff.substr(index + 1);

	Client client(ip, port);
}