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

#ifdef DEBUGGING
	DEBUG("Generated public key (" << pubkey.size() << " bytes):");
	hexify((const unsigned char*)pubkey.c_str(), pubkey.size());

	DEBUG("Generated private key (" << privkey.size() << " bytes):");
	hexify((const unsigned char*)privkey.c_str(), privkey.size());
#endif
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
	DEBUG("Payload size: " << header.getPayloadSize());
	DEBUG("Response code: " << header.getCode());
	DEBUG("Response version: " << (uint8_t)(header.getVersion()));

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
	DEBUG("Getting clients...");

	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::reqClientList);
	request.pack_payloadSize(0);

	sendRequest();

	//Get response
	
	try {
		//Get only the header, for now
		ResponseHeader header = recvResponseHeader(ResponseCodes::listUsers);

		DEBUG("Get clients response is success!");

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
	DEBUG("Getting public key...");

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

#ifdef DEBUGGING
		DEBUG("Client ID: ");
		hexify((const unsigned char*)dest_clientId, S_CLIENT_ID);
		DEBUG("Public key (" << S_PUBLIC_KEY << " bytes): ");
		hexify((const unsigned char*)pubKey, S_PUBLIC_KEY);
#endif

		memcpy(result, pubKey, S_PUBLIC_KEY);

		DEBUG("Got public key!");
	}
	catch (exception& e) {
		LOG(e.what());
	}
	
}

const unsigned char* Client::recvNextPayload(uint32_t amountRecvBytes) const {
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

void Client::recvClientId(ClientId& result) const {
	DEBUG("Receiving client id...");
	auto payload = recvNextPayload(S_CLIENT_ID);
	memcpy(result, payload, S_CLIENT_ID);
	delete[] payload;
	DEBUG("Client ID recevied");
}

void Client::recvUsername(Username& result) const {
	auto payload = recvNextPayload(S_USERNAME);
	memcpy(result, payload, S_USERNAME);
	delete[] payload;
}

void Client::recvPublicKey(PublicKey& result) const {
	DEBUG("Receiving public key...");
	auto payload = recvNextPayload(S_PUBLIC_KEY);
	memcpy(result, payload, S_PUBLIC_KEY);
	delete[] payload;
	DEBUG("Recevied public key");
}

MessageId Client::recvMessageId() {
	DEBUG("Receiving message id...");
	auto payload = recvNextPayload(sizeof(MessageId));
	BufferReader reader(payload, sizeof(MessageId));
	MessageId result = reader.read4bytes();
	delete[] payload;
	DEBUG("Recevied message id");
	return result;
}

MessageType Client::recvMessageType() {
	DEBUG("Receving message type...");
	auto payload = recvNextPayload(sizeof(MessageType));
	BufferReader reader(payload, sizeof(MessageType));
	MessageType msgType = reader.read1byte();
	delete[] payload;
	DEBUG("Recevied message type");
	return msgType;
}

MessageSize Client::recvMessageSize() {
	DEBUG("Receving message size...");
	auto payload = recvNextPayload(sizeof(MessageSize));
	BufferReader reader(payload, sizeof(MessageSize));
	MessageSize msgSize = reader.read4bytes();
	delete[] payload;
	DEBUG("Recevied message size");
	return msgSize;
}

void Client::getSymKey(const ClientId& my_clientId, const ClientId& dest_clientId) {
	DEBUG("Sending symmetric key request...");

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

	LOG("Response from server is success!");
#ifdef DEBUGGING
	DEBUG("Client destination: ");
	hexify((const unsigned char*)response_dest_client_id, S_CLIENT_ID);
	LOG("And message ID: " << messageId);
#endif
}

const vector<MessageResponse>* Client::pullMessages(const ClientId& client_id, const vector<MessageU_User>& users) {
	DEBUG("Pulling waiting messages...");

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

		//IMPORTANT: We don't add message of type 'file' or 'text', only 'symm key' type. This is due to big files and big messages.
		vector<MessageResponse>* messages_pulled = new vector<MessageResponse>();

		//While we have payload to read
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
			//Set response username
			memcpy(msgResponse.sender.username, sender.getUsername().c_str(), S_USERNAME);
			//Check username not null (that we found the sender from users vector)
			if (is_zero_filled(msgResponse.sender.username, S_USERNAME)) {
				LOG("ERROR: Couldn't map username to client id: ");
				hexify((const unsigned char*)msgResponse.sender.client_id, S_CLIENT_ID);
				throw exception("Couldn't convert client id to username, in order to display the message.");
			}
			//Get sender symm key
			SymmetricKey senderSymmKey;
			sender.getSymmetricKey(senderSymmKey);



			//Print message
			cout << endl;
			cout << "From: " << msgResponse.sender.username << endl;
			cout << "Content: " << endl;

			//cast to enum
			MessageTypes _msg_msgType_enum = MessageTypes(msgResponse.msgType); 

			//Check type of message, and display diffirent contents based on that.
			if (_msg_msgType_enum == MessageTypes::reqSymmetricKey) {
				DEBUG("Handling message type: 'request symmetric key'...");
				cout << "Request for symmetric key" << endl;
			}
			else if (_msg_msgType_enum == MessageTypes::sendSymmetricKey) {
				DEBUG("Handling message type: 'send symmetric key'...");
				
				//Get symmetric key (message content) from server
				const unsigned char* msg_msgContent = recvNextPayload(msgResponse.msgSize);
				pSize -= msgResponse.msgSize;

				cout << "Symmetric key received!" << endl;

				msgResponse.msgContent = msg_msgContent; //this is pointer
			}
			else if (_msg_msgType_enum == MessageTypes::sendMessage) {
				DEBUG("Handling message type: 'send message'...");

				// Check valid symm key (if non-zero)
				if (is_zero_filled(senderSymmKey, S_SYMMETRIC_KEY)) {
					cout << "Can't decrypt message! Symmetric key is empty." << endl;
					cout << "----<EOM>-----\n" << endl;
					break;
				}

				//Read entire message by chunks
				string message_cipher;

				size_t msg_bytes_left = msgResponse.msgSize;
				while (msg_bytes_left > 0) {
					//Read chunk
					char buffer[S_PACKET_SIZE] = { 0 };
					size_t bytes_recv = 0;

					//We may get 2 messages in a row. If that happens, we want to receive exact amount of payload of message 1, and not receive 1024 bytes of msg1 and msg2.
					if (msg_bytes_left < S_PACKET_SIZE) {
						bytes_recv = this->socket->receive(boost::asio::buffer(buffer, msg_bytes_left));
					}
					else {
						bytes_recv = this->socket->receive(boost::asio::buffer(buffer, S_PACKET_SIZE));
					}

					string chunk(buffer, bytes_recv); // Convert to string

					//Append
					message_cipher += chunk;

					pSize -= bytes_recv;
					msg_bytes_left -= bytes_recv;
				}
				if (msg_bytes_left != 0) {
					throw runtime_error("Client finished reading message, even though message content size (bytes left to read) is not equal to zero.");
				}

				//Got all the message
				//Decrypt message
				DEBUG("Decrypting message (" << message_cipher.size() << " bytes)...");
				AESWrapper aeswrapper(senderSymmKey, S_SYMMETRIC_KEY);
				string plain = aeswrapper.decrypt((const char*)message_cipher.c_str(), message_cipher.size());
				DEBUG("Successfully decrypted! Plain size: " << plain.size());

				//Print message, end with new line
				cout << plain << endl;
			}
			else if (_msg_msgType_enum == MessageTypes::sendFile) {
				DEBUG("Handling message type: 'send file'...");

				// Check valid symm key (if non-zero)
				if (is_zero_filled(senderSymmKey, S_SYMMETRIC_KEY)) {
					cout << "Can't decrypt file! Symmetric key is empty." << endl;
					cout << "----<EOM>-----\n" << endl;
					break;
				}

				//Create temporary file
				boost::filesystem::path temp_path = boost::filesystem::unique_path();
				boost::filesystem::ofstream temp_file;
				auto file_abs_path = boost::filesystem::system_complete(temp_path);
				
				DEBUG("Saving file to: " << file_abs_path);

				//Open with binary mode write mode
				temp_file.open(temp_path, std::ios::binary);

				string file_cipher;

				//Read file from server, chunk by chunk
				size_t msg_bytes_left = msgResponse.msgSize;
				while (msg_bytes_left > 0) {
					DEBUG("Getting chunk...");
					
					//We read S_PACKET_SIZE but we may end up reading less. Thats why we cast buffer into string.
					char buffer[S_PACKET_SIZE] = { 0 };
					size_t bytes_recv = this->socket->receive(boost::asio::buffer(buffer, S_PACKET_SIZE));
					string chunk(buffer, bytes_recv);
					DEBUG("Got chunk, size: " << chunk.size());

					file_cipher += chunk;

					pSize -= bytes_recv; //Decrement total payload size left
					msg_bytes_left -= bytes_recv; //Decrement message content size left
				}

				if (pSize != 0) {
					throw runtime_error("Client finished reading message, even though payload size (bytes left to read) is not equal to zero.");
				}
				if (msg_bytes_left != 0) {
					throw runtime_error("Client finished reading message, even though message content size (bytes left to read) is not equal to zero.");
				}

				//Decrypt
				DEBUG("Decrypting file(" << file_cipher.size() << " bytes)...");
				try {
					AESWrapper aeswrapper(senderSymmKey, S_SYMMETRIC_KEY);
					string file_plain = aeswrapper.decrypt((const char*)file_cipher.c_str(), file_cipher.size());
					DEBUG("Successfully decrypted file! Size: " << file_plain.size());

					//Write to file all the file
					temp_file.write(file_plain.c_str(), file_plain.size());
					temp_file.flush();
					temp_file.close();

					DEBUG("Done! File saved!");

					// As per PDF, show saved file location
					cout << "File saved to: " << file_abs_path << endl;
				}
				catch (...) {
					cout << "Could not decrypt the file!" << endl;
				}
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
		
		if (pSize != 0) {
			throw runtime_error("Client finished reading message, even though payload size (bytes left to read) is not equal to zero.");
		}

		LOG("Finished receiving messages. Messages read: " << messages_pulled->size());
		return messages_pulled;
	}
	catch (exception& e) {
		LOG("ERROR: " << e.what());
	}

	DEBUG("Pulled all messages.");
}

void Client::connect() {
	DEBUG("Connecting to server...");
	boost::asio::connect(*socket, *endpoints);
	DEBUG("Connected!");
}

void Client::sendSymKey(const ClientId& myClientId, const SymmetricKey& mySymmKey, const ClientId& dest_clientId, const PublicKey& dest_client_pubKey) {
	DEBUG("Sending my symmetric key...");

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
	DEBUG("Encrypting symm key...");
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
	DEBUG("Server response success!");

	//Get response payload
	ClientId response_dest_client_id;
	recvClientId(response_dest_client_id);
	MessageId messageId = recvMessageId();

#ifdef DEBUGGING
	DEBUG("Response client id: ");
	hexify((const unsigned char*)response_dest_client_id, S_CLIENT_ID);
	DEBUG("Response message id: " << messageId);
#endif

	LOG("Symmetric key sent!");
}

void Client::sendText(const ClientId& myClientId, const ClientId& destClientId, const SymmetricKey& symmkey, const string& text) {
	DEBUG("Sending message...");

	//Request Header
	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::sendMessage);

	//Prepare request message header
	MessageHeader msgHeader;
	msgHeader.messageType = (MessageType)MessageTypes::sendMessage; //Cast enum to its value
	memcpy(msgHeader.dest_clientId, destClientId, S_CLIENT_ID);

	//Encrypt text using symm key
	DEBUG("Encrypting message...");
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

#ifdef DEBUGGING
	DEBUG("Response client id: ");
	hexify((const unsigned char*)response_dest_client_id, S_CLIENT_ID);
	DEBUG("Response message id: " << messageId);
#endif

	LOG("Message sent!");
}

void Client::sendFile(const ClientId& myClientId, const SymmetricKey& symmkey, const ClientId& destClientId, size_t filesize, ifstream& filestream) {
	DEBUG("Sending file...");

	DEBUG("File size: " << filesize);

	//Request Header
	request.pack_clientId(myClientId);
	request.pack_version();
	request.pack_code(RequestCodes::sendMessage);

	//Prepare request message header
	MessageHeader msgHeader;
	msgHeader.messageType = (MessageType)MessageTypes::sendFile; //Cast enum to its value
	memcpy(msgHeader.dest_clientId, destClientId, S_CLIENT_ID);

	//Calculate encrypted file size and set as content size.
	size_t file_cipher_size = calc_cipher_size(filesize);
	msgHeader.contentSize = file_cipher_size;

	//Pack payload size
	PayloadSize payloadSize = sizeof(msgHeader) + msgHeader.contentSize;
	request.pack_payloadSize(payloadSize);

	//Pack message header
	request.pack_message_header(msgHeader);

	//We don't pack payload, for now. We send it later.

	//Send the request, need to send the rest of the message content
	sendRequest();

	//Read entire file
	ostringstream ostrm;
	ostrm << filestream.rdbuf();
	string file_content(ostrm.str());

	//Encrypt entire file
	AESWrapper aeswrapper(symmkey, S_SYMMETRIC_KEY);
	string cipher = aeswrapper.encrypt((const char*)file_content.c_str(), file_content.size()); 

	//Send file by chunks
	for (size_t i = 0; i < cipher.size(); i += S_PACKET_SIZE) {
		string packet = cipher.substr(i, S_PACKET_SIZE);
		DEBUG("Sending file content (" << packet.size() << " bytes)...");
		auto buff = boost::asio::buffer(packet);
		this->socket->send(buff);
	}

	//We finished sending the entire cipher.

	LOG("File sent!");
}

size_t Client::calc_cipher_size(size_t plain_size) {
	return ((plain_size / 16) + 1) * 16;
}