#include "FileManager.h"

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
		throw exception("Couldn't properly read client id from the file. (Hex size is not 16)");
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

const char* FileManager::getSavedPrivateKey() {
	ifstream file(FILE_REGISTER);

	string line1, line2;
	getline(file, line1);
	getline(file, line2);

	char* private_key = new char[S_FILE_REGISTER];
	memset(private_key, 0, S_FILE_REGISTER);

	file.read(private_key, S_FILE_REGISTER);

	return private_key;
}