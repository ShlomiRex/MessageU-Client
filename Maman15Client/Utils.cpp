#include "Utils.h"

using namespace std;
using namespace MessageUProtocol;

void hexify(const unsigned char* buffer, unsigned int length)
{
    ios::fmtflags f(cout.flags());
    for (size_t i = 0; i < length; i++) {
        if ((i != 0) && ((i % 16) == 0)) {
            cout << endl;
        }
        cout << hex << setfill('0') << setw(2) << (0xFF & buffer[i]) << " ";
    }
    cout << endl;
    cout.flags(f);
}

string hexify_str(const unsigned char* buffer, size_t length) {
	stringstream ss;
	ss << hex;

	for (size_t i = 0; i < length; ++i) {
		ss << setfill('0') << setw(2) << (0xFF & buffer[i]) << " ";
	}
	return ss.str();
}

bool is_number(const std::string& s)
{
	std::string::const_iterator it = s.begin();
	while (it != s.end() && std::isdigit(*it)) ++it;
	return !s.empty() && it == s.end();
}

bool is_zero_filled(const unsigned char* arr, size_t s_arr)
{
    for (size_t i = 0; i < s_arr; i++) {
        //If not zero, return false, arr is not zero filled
        if (arr[i] != '\0') {
            return false;
        }
    }
    return true;
}

bool buffer_compare(const unsigned char* buff1, const unsigned char* buff2, size_t s_buffers)
{
    for (size_t i = 0; i < s_buffers; i++) {
        char c1 = buff1[i];
        char c2 = buff2[i];
        if (c1 != c2) {
            return false;
        }
    }
    return true;
}

void str_to_pubKey(const std::string& str, PublicKey& result)
{
    memcpy(result, str.c_str(), S_PUBLIC_KEY);
}

void str_to_symmKey(const std::string& str, MessageUProtocol::SymmetricKey& result)
{
    memcpy(result, str.c_str(), S_SYMMETRIC_KEY);
}
