#include "Utils/FileManager.h"

#define DEBUG_PREFIX "[FileManager] "

using namespace std;
using namespace MessageUProtocol;

void FileManager::getSavedClientId(ClientId buffer) {
	DEBUG("Getting my own client id, reading from file: " << FILE_REGISTER);
	ifstream file(FILE_REGISTER);

	if (file.is_open() == false) {
		throw InfoFileNotExistException();
	}

	string line1, line2;
	getline(file, line1);
	getline(file, line2);

	// Remove spaces
	auto noSpaceEnd = std::remove(line2.begin(), line2.end(), ' ');
	line2.erase(noSpaceEnd, line2.end());

	string hash = boost::algorithm::unhex(line2);
	if (hash.size() != S_CLIENT_ID) {
		throw "Couldn't properly read client id from the file. (Hex size is not 16)";
	}

	for (size_t i = 0; i < S_CLIENT_ID; i++) {
		buffer[i] = hash.at(i);
	}


}

string FileManager::getSavedUsername() {
	ifstream file(FILE_REGISTER);

	string line1;
	getline(file, line1);

	return line1;
}

string FileManager::getSavedPrivateKey() {
	ifstream file(FILE_REGISTER);

	string line1, line2;
	getline(file, line1);
	getline(file, line2);
	
	
	char buffer[S_FILE_REGISTER] = { 0 };
	file.read(buffer, S_FILE_REGISTER);
	string line3(buffer);
	
	return line3;
}

void FileManager::readServer(string& result_ip, string& result_port) {
	DEBUG("Reading from " << FILE_SERVER);
	ifstream server_info(FILE_SERVER);
	char buff[S_FILE_SERVER] = { 0 };
	server_info.read(buff, S_FILE_SERVER);
	string str_buff = buff;
	size_t index = str_buff.find(':');

	string ip = str_buff.substr(0, index);
	string port = str_buff.substr(index + 1);

	if (ip.size() == 0 && port.size() == 0) {
		stringstream ss;
		ss << "ERROR: IP or port is empty. Check " << FILE_SERVER;
		throw ss.str();
	}

	DEBUG("IP: " << ip);
	DEBUG("Port: " << port);

	result_ip = ip;
	result_port = port;
}