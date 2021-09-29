#include "Client.h"

using namespace std;
using namespace MessageUProtocol;

#define DEBUG_PREFIX "[Client] "

Client::Client(const string& ip, const string& port, const Version clientVersion) : request(clientVersion) {
	//Initialize all internal fields and connect to server.

	this->io_context = new boost::asio::io_context();
	this->socket = new boost::asio::ip::tcp::socket(*io_context);
	this->resolver = new boost::asio::ip::tcp::resolver(*io_context);
	this->endpoints = new boost::asio::ip::tcp::resolver::results_type();

	*this->endpoints = resolver->resolve(ip, port);
}

Client::~Client() {
	delete io_context;
	delete socket;
	delete resolver;
	delete endpoints;
}

void Client::registerUser(const string& username, ClientId& result_clientId) {
	LOG("Registering user...");

	//Check if the info file exists
	if (boost::filesystem::exists(FILE_REGISTER)) {
		LOG(FILE_REGISTER << " already exists! Already registered.");
		return;
	}

	ClientId myClientId = { 0 };
	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::registerUser);

	//Payload size: name (with null terminator) + public key
	request.pack_payloadSize(S_USERNAME + S_PUBLIC_KEY);

	//Payload: Name
	request.pack_username(username);

	//Payload: Public key

	//Generate key pairs
	RSAPrivateWrapper rsaPrivWrapper;
	string privkey = rsaPrivWrapper.getPrivateKey();
	string pubkey = rsaPrivWrapper.getPublicKey();

	LOG("Generated public key (" << pubkey.size() << " bytes):");
	hexify((const unsigned char*)pubkey.c_str(), pubkey.size());

	LOG("Generated private key (" << privkey.size() << " bytes):");
	hexify((const unsigned char*)privkey.c_str(), privkey.size());

	//Test other clients can encrypt with my public key
	{
		RSAPublicWrapper rsaPub(pubkey);
		string plain = "Hello World!";
		string cipher = rsaPub.encrypt(plain);

		//Test I can read encrypted messages
		{
			RSAPrivateWrapper rsaPriv(privkey);
			string decrypted = rsaPriv.decrypt(cipher);
			assert(decrypted.compare(plain) == 0);
		}
	}

	//Pack public key
	PublicKey my_publicKey = { 0 };
	memcpy(my_publicKey, pubkey.c_str(), pubkey.size());
	request.pack_pub_key(my_publicKey);

	//Send request
	sendRequest();

	//Get response
	try {
		ResponseHeader header = recvResponseHeader(ResponseCodes::registerSuccess);

		ClientId dest_clientId;
		recvClientId(dest_clientId);

		//Save client id got from server
		memcpy(result_clientId, dest_clientId, S_CLIENT_ID);

		LOG("Registeration was a success! Client ID got from server:");
		hexify((const unsigned char*)dest_clientId, S_CLIENT_ID);

		DEBUG("Writing username and client id to file: " << FILE_REGISTER);

		//In the first line, write sender_username
		ofstream file(FILE_REGISTER);
		file << username << endl;
		file.flush();
		file.close();

		//In the second line, write the client id in human readable space seperated hex.
		file.open(FILE_REGISTER, ios::app);
		string str_clientid = hexify_str(dest_clientId, S_CLIENT_ID);
		file.write(str_clientid.c_str(), str_clientid.size());
		file.write("\n", 1);

		//In the third line, write private key
		string base64 = Base64Wrapper::encode(privkey);
		file.write(base64.c_str(), base64.size());

		//Finish
		file.close();
		DEBUG("Done writing");

		LOG("Register success!");
	}
	catch (exception& e) {
		LOG(e.what());
	}
}

size_t Client::sendRequest() {
	size_t packetSize = request.getPacketSize();
	auto buff = request.getPacket();

	DEBUG("Sending request (" << packetSize << " bytes): ");
#ifdef DEBUGGING
	hexify((const unsigned char*)buff, packetSize);
#endif
	size_t bytesSent = this->socket->send(boost::asio::buffer(buff, packetSize));
	DEBUG("Sent " << bytesSent << " bytes!");
	return bytesSent;
}

ResponseHeader Client::recvResponseHeader(ResponseCodes requiredCode) {
	DEBUG("Receving response header...");
	auto payload = recvNextPayload(S_RESPONSE_HEADER);
	DEBUG("Received response header");

	ResponseHeader header(payload, S_RESPONSE_HEADER);

	//It's fine to free memory, header copied.
	delete[] payload;

	//Parse code
	ResponseCodes _code = static_cast<ResponseCodes>(header.getCode());
	if (_code == ResponseCodes::error) {
		throw ResponseErrorException();
	}
	else if (_code != requiredCode) {
		int req = static_cast<int>(requiredCode);
		int got = static_cast<int>(header.getCode());
		throw InvalidResponseCodeException(req, got);
	}

	return header;
}

void Client::getClients(const ClientId& myClientId, vector<User>* result) {
	LOG("Getting clients...");

	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::reqClientList);
	request.pack_payloadSize(0);

	sendRequest();

	//Get response
	
	try {
		//Get only the header, for now
		ResponseHeader header = recvResponseHeader(ResponseCodes::listUsers);

		LOG("Get clients response is success!");

		//We need to read s_payload
		size_t payloadBytesRead = 0;
		size_t s_users = 0;
		cout << endl;

		while (payloadBytesRead < header.getPayloadSize()) {
			s_users += 1;

			User user = recvNextUserInList();
			payloadBytesRead += sizeof(user);

			result->push_back(user);

			LOG("User " << s_users << ": " << user.username);
			LOG("Client ID:");
			hexify((const unsigned char*)user.client_id, S_CLIENT_ID);
			cout << endl;
		}
		LOG("Done listing " << s_users << " users.");
	}
	catch (exception& e) {
		LOG(e.what());
	}

}

void Client::getPublicKey(const ClientId& myClientId, const ClientId& dest_client_id, PublicKey& result) {
	LOG("Getting public key...");

	//Pack header
	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::reqPublicKey);
	request.pack_payloadSize(S_CLIENT_ID);
	
	//Pack payload
	request.pack_clientId(dest_client_id);

	//Send request
	sendRequest();

	//Get response
	try {
		ResponseHeader header = recvResponseHeader(ResponseCodes::publicKey);

		ClientId dest_clientId = { 0 };
		PublicKey pubKey = { 0 };
		recvClientId(dest_clientId);
		recvPublicKey(pubKey);

		LOG("Client ID: ");
		hexify((const unsigned char*)dest_clientId, S_CLIENT_ID);
		LOG("Public key (" << S_PUBLIC_KEY << " bytes): ");
		hexify((const unsigned char*)pubKey, S_PUBLIC_KEY);

		memcpy(result, pubKey, S_PUBLIC_KEY);
	}
	catch (exception& e) {
		LOG(e.what());
	}
	
}

const unsigned char* Client::recvNextPayload(uint32_t amountRecvBytes) {
	if (amountRecvBytes == 0)
		return nullptr;

	DEBUG("Receving payload...");
	unsigned char* buffer = new unsigned char[amountRecvBytes];
	memset(buffer, 0, amountRecvBytes);

	size_t bytes_recv = this->socket->receive(boost::asio::buffer(buffer, amountRecvBytes));
	DEBUG("Received payload (" << bytes_recv << " bytes): ");
#ifdef DEBUGGING
	hexify((const unsigned char*)buffer, bytes_recv);
#endif

	if (bytes_recv != amountRecvBytes) {
		LOG("ERROR: Requested to receive " << amountRecvBytes << " bytes, but got only " << bytes_recv << " bytes!");
	}

	return buffer;
}

User Client::recvNextUserInList() {
	User result;

	this->recvClientId(result.client_id);
	this->recvUsername(result.username);

	return result;
}

void Client::recvClientId(ClientId& result) {
	auto payload = recvNextPayload(S_CLIENT_ID);
	memcpy(result, payload, S_CLIENT_ID);
	delete[] payload;
}

void Client::recvUsername(Username& result) {
	auto payload = recvNextPayload(S_USERNAME);
	memcpy(result, payload, S_USERNAME);
	delete[] payload;
}

void Client::recvPublicKey(PublicKey& result) {
	auto payload = recvNextPayload(S_PUBLIC_KEY);
	memcpy(result, payload, S_PUBLIC_KEY);
	delete[] payload;
}

MessageId Client::recvMessageId() {
	auto payload = recvNextPayload(sizeof(MessageId));
	BufferReader reader(payload, sizeof(MessageId));
	MessageId result = reader.read4bytes();
	delete[] payload;
	return result;
}

MessageType Client::recvMessageType() {
	auto payload = recvNextPayload(sizeof(MessageType));
	BufferReader reader(payload, sizeof(MessageType));
	MessageType msgType = reader.read1byte();
	delete[] payload;
	return msgType;
}

MessageSize Client::recvMessageSize() {
	auto payload = recvNextPayload(sizeof(MessageSize));
	BufferReader reader(payload, sizeof(MessageSize));
	MessageSize msgSize = reader.read4bytes();
	delete[] payload;
	return msgSize;
}

void Client::getSymKey(const ClientId& my_clientId, const ClientId& dest_clientId) {
	LOG("Sending symmetric key request...");

	//Request Header
	request.pack_clientId(my_clientId);
	request.pack_version();
	request.pack_code(RequestCodes::sendMessage);

	//Payload is depends on message type and such, let it do the hard work

	//Create message header and set it's fields
	MessageHeader msgHeader;
	memcpy(msgHeader.dest_clientId, dest_clientId, S_CLIENT_ID);
	msgHeader.messageType = (MessageType)MessageTypes::reqSymmetricKey; //Cast enum (MessageTypes, abstract) to MessageType (what we send)
	msgHeader.contentSize = 0; //We don't send anything in message

	//Create message request from header
	MessageRequest msg(msgHeader);

	//Now convert the message to payload for the base request
	ContentSize payloadSize = 0;
	auto payload = msg.pack(&payloadSize);

	//Set base request payload size
	request.pack_payloadSize(payloadSize);
	request.pack_payload(payload, payloadSize);

	//Finnaly, send request
	sendRequest();
	//We can free payload memory, we don't use it anymore
	delete[] payload;

	//Get respose from server
	ResponseHeader header = recvResponseHeader(ResponseCodes::messageSent);
	ClientId response_dest_client_id;
	recvClientId(response_dest_client_id);
	MessageId messageId = recvMessageId();

	LOG("Response from server is success! Client destination: ");
	hexify((const unsigned char*)response_dest_client_id, S_CLIENT_ID);
	LOG("And message ID: " << messageId);
}

const vector<MessageResponse>* Client::pullMessages(const ClientId& client_id, const vector<MessageU_User>& users) {
	LOG("Pulling waiting messages...");

	//Request Header
	request.pack_clientId(client_id);
	request.pack_version();
	request.pack_code(RequestCodes::reqPullWaitingMessages);
	request.pack_payloadSize(0);

	//Send request
	sendRequest();

	//Get waiting messages
	try {
		ResponseHeader header = recvResponseHeader(ResponseCodes::pullWaitingMessages);
		PayloadSize payloadSize = header.getPayloadSize();
		PayloadSize pSize = payloadSize;
		size_t message_num = 0;
		
		if (payloadSize == 0) {
			LOG("No messages waiting for you, sir!");
			return nullptr;
		}

		vector<MessageResponse>* messages_pulled = new vector<MessageResponse>();

		while (pSize > 0) {
			//Get single message (response from server)
			//Each receive, we substract amount of bytes left to read.

			message_num += 1;

			//Create message response so we can save it and use it later
			MessageResponse msgResponse;
			//Receive header, discard from stack after that, msgResponse encapsulates the data.
			{
				ClientId msg_clientId;
				recvClientId(msg_clientId);
				pSize -= sizeof(ClientId);

				MessageId msg_msgId = recvMessageId();
				pSize -= sizeof(MessageId);

				MessageType msg_msgType = recvMessageType();
				pSize -= sizeof(MessageType);

				MessageSize msg_msgSize = recvMessageSize();
				pSize -= sizeof(MessageSize);

				//Set response
				memcpy(msgResponse.sender.client_id, msg_clientId, S_CLIENT_ID);
				memset(msgResponse.sender.username, 0, S_USERNAME);
				msgResponse.msgId = msg_msgId;
				msgResponse.msgType = msg_msgType;
				msgResponse.msgSize = msg_msgSize;
				msgResponse.msgContent = nullptr;
			}


			//Get sender
			MessageU_User sender;
			for (const auto& x : users) {
				ClientId xClientId;
				x.getClientId(xClientId);

				bool same = buffer_compare(msgResponse.sender.client_id, xClientId, S_CLIENT_ID);
				if (same) {
					sender = x;
					break;
				}
			}
			//Get sender username
			memcpy(msgResponse.sender.username, sender.getUsername().c_str(), S_USERNAME);

			if (is_zero_filled(msgResponse.sender.username, S_USERNAME)) {
				LOG("ERROR: Couldn't map username to client id: ");
				hexify((const unsigned char*)msgResponse.sender.client_id, S_CLIENT_ID);
				throw exception("Couldn't convert client id to username, in order to display the message.");
			}

			//Print message
			cout << endl;
			cout << "From: " << msgResponse.sender.username << endl;
			cout << "Content: " << endl;

			//Check type of message, and display diffirent contents based on that.
			MessageTypes _msg_msgType_enum = MessageTypes(msgResponse.msgType);
			if (_msg_msgType_enum == MessageTypes::reqSymmetricKey) {
				cout << "Request for symmetric key" << endl;
			}
			else if (_msg_msgType_enum == MessageTypes::sendSymmetricKey) {
				cout << "Symmetric key received" << endl;
				
				//Get symmetric key (message content) from server
				const unsigned char* msg_msgContent = recvNextPayload(msgResponse.msgSize);
				pSize -= msgResponse.msgSize;

				msgResponse.msgContent = msg_msgContent; //this is pointer
			}
			else if (_msg_msgType_enum == MessageTypes::sendMessage) {
				//TODO: Decrypt
				size_t msg_bytes_left = msgResponse.msgSize;
				size_t msg_bytes_read = 0;
				while (msg_bytes_left > 0) {
					MessageContent msg_content = nullptr;

					//If we can read more than 1 packet
					if (msg_bytes_left > S_PACKET_SIZE) {
						auto content = recvNextPayload(S_PACKET_SIZE);
						msg_bytes_read = S_PACKET_SIZE; //Save amount of bytes read
						pSize -= S_PACKET_SIZE; //Decrease total payload size left
						msg_bytes_left -= S_PACKET_SIZE;  //Decrease message content payload size left

						msg_content = content;
					}
					else {
						auto content = recvNextPayload(msg_bytes_left);
						msg_bytes_read = msg_bytes_left; //Save amount of bytes read
						pSize -= msg_bytes_left; //Decrease total payload size left
						msg_bytes_left -= msg_bytes_left; //Decrease message content payload size left (in this case, we left with zero, and exit loop)

						msg_content = content;
					}

					//Get sender symm key
					SymmetricKey senderSymmKey;
					sender.getSymmetricKey(senderSymmKey);

					//Decrypt cipher with sender's symm key
					AESWrapper aeswrapper(senderSymmKey, S_SYMMETRIC_KEY);
					string plain = aeswrapper.decrypt((const char*)msg_content, msg_bytes_read);

					//Print chiper's plain text block, without newline
					cout << plain;

					//Free payload
					delete[] msg_content;
				}
				//Got all the message
				//End text message content with newline
				cout << endl;
			}
			else {
				LOG("ERROR: Message type: " << (int)msgResponse.msgType << " is not recognized.");
				throw exception("Message type invalid.");
			}

			//Finish content
			cout << "----<EOM>-----\n" << endl;

			//Add to pulled messages
			messages_pulled->push_back(msgResponse);
		}
		LOG("Finished receiving messages. Messages read: " << messages_pulled->size());
		return messages_pulled;
	}
	catch (exception& e) {
		LOG("ERROR: " << e.what());
	}
}

void Client::connect() {
	DEBUG("Connecting to server...");
	boost::asio::connect(*socket, *endpoints);
	DEBUG("Connected!");
}

void Client::sendSymKey(const ClientId& myClientId, const SymmetricKey& mySymmKey, const ClientId& dest_clientId, const PublicKey& dest_client_pubKey) {
	LOG("Sending my symmetric key...");

	//Request Header
	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::sendMessage);

	//Prepare request message header
	MessageHeader msgHeader;
	msgHeader.messageType = (MessageType)MessageTypes::sendSymmetricKey; //Cast enum to its value
	memcpy(msgHeader.dest_clientId, dest_clientId, S_CLIENT_ID);

	//string tmp_pubkey(dest_client_pubKey); //THIS WHAT CAUSED A LOT OF ISSUES AND I SPENT TONS OF TIME DEBUGGING WHY I GET DER DECODE ERROR.
	//APPERANTLY, STRING STOPS AT TERMINATOR. BUT IN OUR CASE, WE WANT TERMINATORS INSIDE THE STRING.
	string pubkey_str = buffer_to_str(dest_client_pubKey, S_PUBLIC_KEY);

	//Encrypt symm key
	RSAPublicWrapper rsapub(pubkey_str);
	string cipher = rsapub.encrypt((char*)mySymmKey);

	//Set message content size
	msgHeader.contentSize = cipher.size();

	//Pack payload size
	PayloadSize payloadSize = sizeof(msgHeader) + msgHeader.contentSize;
	request.pack_payloadSize(payloadSize);

	//Pack message header
	request.pack_message_header(msgHeader);

	//Pack message content
	request.pack_payload((const unsigned char*)cipher.c_str(), cipher.size());

	//Go
	sendRequest();


	//Get response
	ResponseHeader header = recvResponseHeader(ResponseCodes::messageSent);
	LOG("Server response success!");

	//Get response payload
	ClientId response_dest_client_id;
	recvClientId(response_dest_client_id);
	MessageId messageId = recvMessageId();

	LOG("Response client id: ");
	hexify((const unsigned char*)response_dest_client_id, S_CLIENT_ID);
	LOG("Response message id: " << messageId);

	LOG("Symmetric key sent!");
}

void Client::sendText(const ClientId& myClientId, const ClientId& destClientId, const SymmetricKey& symmkey, const string& text) {
	LOG("Sending message...");

	//Request Header
	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::sendMessage);

	//Prepare request message header
	MessageHeader msgHeader;
	msgHeader.messageType = (MessageType)MessageTypes::sendMessage; //Cast enum to its value
	memcpy(msgHeader.dest_clientId, destClientId, S_CLIENT_ID);

	//Encrypt text using symm key
	AESWrapper aeswrapper(symmkey, S_SYMMETRIC_KEY);
	string cipher = aeswrapper.encrypt(text.c_str(), text.size());

	//Set message content size
	msgHeader.contentSize = cipher.size();

	//Pack payload size
	PayloadSize payloadSize = sizeof(msgHeader) + msgHeader.contentSize;
	request.pack_payloadSize(payloadSize);

	//Pack message header
	request.pack_message_header(msgHeader);

	//Pack message content
	request.pack_payload((const unsigned char*)cipher.c_str(), cipher.size());

	//Go
	sendRequest();


	//Get response
	ResponseHeader header = recvResponseHeader(ResponseCodes::messageSent);
	LOG("Server response success!");

	//Get response payload
	ClientId response_dest_client_id;
	recvClientId(response_dest_client_id);
	MessageId messageId = recvMessageId();

	LOG("Response client id: ");
	hexify((const unsigned char*)response_dest_client_id, S_CLIENT_ID);
	LOG("Response message id: " << messageId);

	LOG("Message sent!");
}

void Client::sendFile(const ClientId& myClientId, const SymmetricKey& symmkey, const ClientId& destClientId, size_t filesize, ifstream& filestream) {
	LOG("Sending file...");

	//Calculate amount of bytes to send to server
	size_t s_chunk = S_PACKET_SIZE;										//Amount of desired bytes to read from file and send
	size_t s_cipher_chunk = (s_chunk / 16 + 1) * 16;					//Amount of bytes needed for each chunk, after AES-CBS encryption, source: https://stackoverflow.com/a/3284136
	size_t num_chunks = (filesize / s_chunk) + 1;						//Number of chunks in total we want to send. If filesize < s_chunk then we still need to send 1 chunk, not 0. So add 1.
	size_t total_file_cipher_size = num_chunks * s_cipher_chunk;		//Total amount of bytes we need to send for encrypted chunks


	//Request Header
	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::sendMessage);

	//Prepare request message header
	MessageHeader msgHeader;
	msgHeader.messageType = (MessageType)MessageTypes::sendFile; //Cast enum to its value
	memcpy(msgHeader.dest_clientId, destClientId, S_CLIENT_ID);
	msgHeader.contentSize = total_file_cipher_size;						//Here we set the amount of bytes we want to send

	//Pack payload size
	PayloadSize payloadSize = sizeof(msgHeader) + msgHeader.contentSize;
	request.pack_payloadSize(payloadSize);

	//Pack message header
	request.pack_message_header(msgHeader);

	//We don't pack payload, for now

	//Send the request, need to send the rest of the message content
	sendRequest();

	size_t bytes_left_to_read = filesize;
	AESWrapper aeswrapper(symmkey, S_SYMMETRIC_KEY);
	char read_buffer[S_PACKET_SIZE] = { 0 };
	while (bytes_left_to_read > 0) {
		//Read from file
		if (bytes_left_to_read < S_PACKET_SIZE) {
			filestream.read(read_buffer, bytes_left_to_read);
			bytes_left_to_read -= bytes_left_to_read; //Equal to zero
		}
		else {
			filestream.read(read_buffer, S_PACKET_SIZE);
			bytes_left_to_read -= S_PACKET_SIZE;
		}

		//Encrypt text using symm key
		string cipher = aeswrapper.encrypt(read_buffer, S_PACKET_SIZE);
		size_t cipherlen = cipher.size();

		//Send raw bytes, as payload
		this->socket->send(boost::asio::buffer(cipher));

		LOG("Cipher length: " << cipherlen);
	}



	LOG("File sent!");
}