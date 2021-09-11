#include "Utils.h"

using namespace std;

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

string hexify_str(const char* buffer, size_t length) {
	stringstream ss;
	ss << hex;

	for (int i = 0; i < length; ++i) {
		ss << setfill('0') << setw(2) << (0xFF & buffer[i]) << " ";
	}
	return ss.str();
}
