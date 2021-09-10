#include "Utils.h"

using namespace std;

void hexify(const unsigned char* buffer, unsigned int length)
{
	ios::fmtflags f(cout.flags());
	cout << hex;
	for (size_t i = 0; i < length; i++)
		cout << setfill('0') << setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	cout << endl;
	cout.flags(f);
}

string hexify_str(const char* buffer, size_t length) {
	stringstream ss;
	ss << hex;

	for (int i = 0; i < length; ++i) {
		ss << setfill('0') << setw(2) << (0xFF & buffer[i]) << " ";
	}
	return ss.str();
}
