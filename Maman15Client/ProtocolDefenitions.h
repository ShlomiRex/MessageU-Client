#pragma once

#include <cstdint>

//Excplicit defenitions - derrived from the protocol
//====================================================================================
#define S_PACKET_SIZE		1024U			//Default packet read/write size
#define S_USERNAME			255U			//Username key field size
#define S_PUBLIC_KEY		160U			//Public key field size
#define S_CLIENT_ID			16U				//Client ID field size
#define FILE_SERVER			"server.info"	//For starting the server
#define FILE_REGISTER		"me.info"		//For saving registeration information
#define S_RESPONSE_HEADER	7U				//Size of response header
#define S_SYMMETRIC_KEY		16U				//symmetric key length - AES-CBC encryption, decryption
#define S_ASYMMETRIC_KEY	128U			//asymmetric key length - RSA encryption

//Op codes
enum class RequestCodes {
	registerUser = 1000,
	reqClientList = 1001,
	reqPublicKey = 1002,
	sendText = 1003,
	reqPullWaitingMessages = 1004
};

enum class ResponseCodes {
	registerSuccess = 2000,
	listUsers = 2001,
	publicKey = 2002,
	messageSent = 2003,
	pullWaitingMessages = 2004,
	error = 9000
};

enum class MessageTypes {
	reqSymmetricKey = 1,
	sendSymmetricKey = 2,
	sendText = 3,
	sendFile = 4
};

//Implicit defenitions - not explicitly stated in the protocol defenition
//====================================================================================
#define S_FILE_REGISTER		2048U			//Maximum private key size, for buffering
#define S_FILE_SERVER		2048U			//Maximum file size

//Types
//====================================================================================
//Common header fields
typedef char ClientId[S_CLIENT_ID];
typedef uint8_t Version;
typedef uint16_t Code;
typedef uint32_t PayloadSize;
typedef char Username[S_USERNAME];
typedef char PublicKey[S_PUBLIC_KEY];

//Message (Request + Response) header fields
typedef uint8_t MessageType;

//Message Request header fields
typedef uint32_t ContentSize;

//Message Response header fields
typedef uint32_t MessageId;
typedef uint32_t MessageSize;

typedef struct {
	ClientId client_id;
	Username username;
} User;

typedef struct {
	ClientId dest_clientId;
	MessageType msgType;
	ContentSize contentSize;
} SendMsgRequestHeader;


