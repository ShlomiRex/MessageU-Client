#pragma once
enum class ClientChoices {
	registerUser = 10,
	reqClientList = 20,
	reqPublicKey = 30,
	reqWaitingMessages = 40,
	sendText = 50,
	sendReqSymmetricKey = 51,
	sendSymmetricKey = 52,
	sendFile = 53,
	exitProgram = 0
};
