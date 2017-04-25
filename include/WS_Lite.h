#pragma once
#include <memory>
#include <string>
#include <functional>
#include <unordered_map>

namespace SL {
	namespace WS_LITE {
		//forward declares
		struct WSocket;
		class WSListener;

		enum OpCode : unsigned char {
			CONTINUATION=0,
			TEXT = 1,
			BINARY = 2,
			CLOSE = 8,
			PING = 9,
			PONG = 10
		};
		//this is the message after being uncompressed
		struct UnpackedMessage {
			char* data;
			size_t len;
			OpCode code;
		};

		//this contains information about the compressed message size
		struct PackgedMessageInfo {
			size_t len;
		};

		struct WSS_Config{
			std::string Password;
			std::string Privatekey_File;
			std::string Publiccertificate_File;
			std::string dh_File;
		};
	
		std::shared_ptr<WSListener> CreateListener(unsigned short port);
		void StartListening(std::shared_ptr<WSListener>& l);

		std::shared_ptr<WSListener> CreateListener(unsigned short port, const WSS_Config& c);
		void StartListening(std::shared_ptr<WSListener>& l);
		
		void onConnection(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle);
		void onConnection(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle);

		void onMessage(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)>& handle);
		void onMessage(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)>& handle);

		void onDisconnection(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, int code, char *message, size_t length)>& handle);
		void onDisconnection(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, int code, char *message, size_t length)>& handle);

		void onPing(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle);
		void onPing(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle);

		void onPong(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle);
		void onPong(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle);

		void onHttpUpgrade(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>)>& handle);
		void onHttpUpgrade(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>)>& handle);

		void set_MaxPayload(WSListener& s, unsigned long long int bytes);
		void get_MaxPayload(WSListener& s);

		void set_ReadTimeout(WSListener& s,unsigned int seconds);
		void get_ReadTimeout(WSListener& s);
		void set_WriteTimeout(WSListener& s, unsigned int seconds);
		void get_WriteTimeout(WSListener& s);

		void send(const std::shared_ptr<WSocket>& s, const UnpackedMessage& msg);
		bool closed(std::shared_ptr<WSocket>& s);
		std::string get_address(std::shared_ptr<WSocket>& s);
		unsigned short get_port(std::shared_ptr<WSocket>& s);
		bool is_v4(std::shared_ptr<WSocket>& s);
		bool is_v6(std::shared_ptr<WSocket>& s);
		bool is_loopback(std::shared_ptr<WSocket>& s);
	}
}

