#pragma once

#include <cstdint>

//Excplicit defenitions
#define S_PACKET_SIZE		1024U
#define S_USERNAME			255U
#define S_PUBLIC_KEY		160U
#define S_CLIENT_ID			16U
#define FILE_SERVER			"server.info"
#define FILE_REGISTER		"me.info"
#define S_RESPONSE_HEADER	7U	//Size of response header


//Implicit defenitions
#define S_FILE_REGISTER		2048U	//Maximum private key size, for buffering

//Types
//Note: I use typedef only after couple of days of programming. It made my life much easier. It's easier to read.
typedef char ClientId[S_CLIENT_ID];
typedef uint8_t Version;
typedef uint16_t Code;
typedef uint32_t PayloadSize;
typedef char Username[S_USERNAME];
typedef char PublicKey[S_PUBLIC_KEY];