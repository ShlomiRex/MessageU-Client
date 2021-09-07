#pragma once

enum class ClientChoices {
	registerUser = 10,
	reqClientList = 20,
	reqPublicKey = 30,
	reqWaitingMessages = 40,
	sendText = 50,
	sendReqSymmetricKey = 51,
	sendSymmetricKey = 52,
	exitProgram = 0
};

enum class RequestCodes {
	registerUser = 1000,
	reqClientList = 1001,
	reqPublicKey = 1002,
	sendText = 1003,
	reqWaitingMessages = 1004
};

enum class MessageType {
	reqSymmetricKey = 1,
	sendSymmetricKey = 2,
	sendText = 3,
	sendFile = 4
};

enum class ResponseCodes {
	registerSuccess = 2000,
	listUsers = 2001,
	publicKey = 2002,
	messageSent = 2003,
	pullWaitingMessages = 2004,
	error = 9000
};