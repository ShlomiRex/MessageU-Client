#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <exception>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "Base64Wrapper.h"
#include <iomanip>
#include "BufferUtils.h"
#include "ProtocolDefenitions.h"
#include "Response.h"
#include "Request.h"
#include "Utils.h"
#include <algorithm>
#include "FileManager.h"
#include "MessageRequest.h"
#include "Debug.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "MessageU_User.h"
#include <fstream>
#pragma comment(lib, "Ws2_32.lib")

//using namespace std; //bad practice
//using namespace MessageUProtocol; //bad practice

//Client holds a single request buffer. Because the protocol is stateless, we only send ONE request, per client object.
//The responses, however, can be more than 1 packet.

class Client
{
private:
	Request request;
	
	boost::asio::io_context* io_context;
	boost::asio::ip::tcp::socket* socket;
	boost::asio::ip::tcp::resolver* resolver;
	boost::asio::ip::tcp::resolver::results_type* endpoints;

	//Sends this class's request object.
	size_t sendRequest();

	//Receive response header (fixed size). 
	ResponseHeader recvResponseHeader(MessageUProtocol::ResponseCodes requiredCode);
	
	//General function to receive required amount of bytes in socket.
	const unsigned char* recvNextPayload(uint32_t amountRecvBytes) const;

	//Spesific recv functions
	MessageUProtocol::User recvNextUserInList();
	void recvClientId(MessageUProtocol::ClientId& result) const;
	void recvUsername(MessageUProtocol::Username& result) const;
	void recvPublicKey(MessageUProtocol::PublicKey& result) const;
	MessageUProtocol::MessageId recvMessageId();
	MessageUProtocol::MessageType recvMessageType();
	MessageUProtocol::MessageSize recvMessageSize();
	//Receives bytes from socket, doing nothing. (skipping.) (useful for ignoring undecryptable messages)
	void recvNullSink(size_t bytes_to_receive) const;
	//Read the response from the server in chunks.
	void recvChunks(size_t payloadSize, std::string& result) const;

public:
	Client(const std::string& ip, const std::string& port, const MessageUProtocol::Version clientVersion = 1);
	~Client();

	void connect();

	void registerUser(
		const std::string& user,
		MessageUProtocol::ClientId& result_clientId);
	void getClients(
		const MessageUProtocol::ClientId& myClientId,
		std::vector<MessageUProtocol::User>* result);
	void getPublicKey(
		const MessageUProtocol::ClientId& myClientId, 
		const MessageUProtocol::ClientId& dest_client_id, 
		MessageUProtocol::PublicKey& result);
	const std::vector<MessageUProtocol::MessageResponse>* pullMessages(
		const MessageUProtocol::ClientId& client_id, 
		const std::vector<MessageU_User>& users);
	void sendText(
		const MessageUProtocol::ClientId& myClientId,
		const MessageUProtocol::ClientId& destClientId,
		const MessageUProtocol::SymmetricKey& symmkey,
		const std::string& text);
	void getSymKey(
		const MessageUProtocol::ClientId& my_clientId,
		const MessageUProtocol::ClientId& dest_clientId);
	void sendSymKey(
		const MessageUProtocol::ClientId& myClientId,
		const MessageUProtocol::SymmetricKey& mySymmKey,
		const MessageUProtocol::ClientId& dest_clientId,
		const MessageUProtocol::PublicKey& dest_client_pubKey);
	void sendFile(
		const MessageUProtocol::ClientId& myClientId,
		const MessageUProtocol::SymmetricKey& mySymmKey,
		const MessageUProtocol::ClientId& dest_clientId,
		size_t filesize,
		std::ifstream& filestream);

	//Calculates AES-CBS cipher size given the plain size. Source: https://stackoverflow.com/a/3284136
	static size_t calc_cipher_size(size_t plain_size);
};

struct InitSocketException : public std::exception {
	const char* what() const throw () {
		return "Encountered exception while initializing client socket.";
	}
};
