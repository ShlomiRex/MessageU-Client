#pragma once

#include <cstdint>

namespace MessageUProtocol {
//Excplicit defenitions - derrived from the protocol
//====================================================================================
#define S_PACKET_SIZE		1024U			//Default packet read/write size
#define S_USERNAME			255U			//Username key field size
#define S_CLIENT_ID			16U				//Client ID field size
#define S_RESPONSE_HEADER	7U				//Size of response header

#define S_PUBLIC_KEY		160U			//Public key field size
#define S_PRIVATE_KEY		160U	//TODO: PRIVATE KEY SIZE IS NOT 160. IDK WHY YOU SAY IT'S 160 BUTS ITS 633 OR 632.		//key pair with public key for asymmetric encryption, decryption
#define S_SYMMETRIC_KEY		16U				//symmetric key length (in bytes) - AES-CBC encryption, decryption
#define S_ASYMMETRIC_KEY	128U			//asymmetric key length (in bytes) - RSA encryption

#define FILE_SERVER			"server.info"	//For starting the server
#define FILE_REGISTER		"me.info"		//For saving registeration information

//Implicit defenitions
#define S_FILE_REGISTER		2048U			//Maximum size of me.info


//Op codes
	enum class RequestCodes {
		registerUser = 1000,
		reqClientList = 1001,
		reqPublicKey = 1002,
		sendMessage = 1003,
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
		sendMessage = 3,
		sendFile = 4
	};

	//Implicit defenitions - not explicitly stated in the protocol defenition
	//====================================================================================
//#define S_FILE_REGISTER		2048U			//Maximum private key size, for buffering
#define S_FILE_SERVER		2048U			//Maximum file size

//Types
//====================================================================================
//Common header fields
	typedef unsigned char ClientId[S_CLIENT_ID];
	typedef uint8_t Version;
	typedef uint16_t Code;
	typedef uint32_t PayloadSize;
	typedef unsigned char Username[S_USERNAME];
	typedef unsigned char PublicKey[S_PUBLIC_KEY];
	typedef unsigned char PrivateKey[S_PRIVATE_KEY];

	//Message (Request + Response) header fields
	typedef uint8_t MessageType;
	typedef unsigned char SymmetricKey[S_SYMMETRIC_KEY];

	//Message Request header fields
	typedef uint32_t ContentSize;

	//Message Response header fields
	typedef uint32_t MessageId;
	typedef uint32_t MessageSize;
	typedef const unsigned char* MessageContent;

	typedef struct {
		ClientId client_id;
		Username username;
	} User;

	typedef struct {
		User sender;
		MessageId msgId;
		MessageType msgType;
		MessageSize msgSize;
		MessageContent msgContent;
	} MessageResponse;


}

