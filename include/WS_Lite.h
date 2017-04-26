#pragma once
#include <memory>
#include <string>
#include <functional>
#include <unordered_map>

namespace SL {
	namespace WS_LITE {

		const auto HTTP_METHOD = "Method";
		const auto HTTP_PATH = "Path";
		const auto HTTP_VERSION = "Http_Version";
		const auto HTTP_STATUSCODE = "Http_StatusCode";
		const auto HTTP_CONTENTLENGTH = "Content-Length";
		const auto HTTP_CONTENTTYPE = "Content-Type";
		const auto HTTP_CACHECONTROL = "Cache-Control";
		const auto HTTP_LASTMODIFIED = "Last-Modified";
		const auto HTTP_SECWEBSOCKETKEY = "Sec-WebSocket-Key";
		const auto HTTP_SECWEBSOCKETACCEPT = "Sec-WebSocket-Accept";

		const auto HTTP_ENDLINE = "\r\n";
		const auto HTTP_KEYVALUEDELIM = ": ";

		//forward declares
		struct WSocket;
		class WSListener;
		class WSClient;

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
			unsigned long long int  len;
			OpCode code;
		};

		//this contains information about the compressed message size
		struct PackgedMessageInfo {
			unsigned long long int  len;
		};


		std::shared_ptr<WSListener> CreateListener(unsigned short port);
		std::shared_ptr<WSListener> CreateListener(
			unsigned short port, 
			std::string Password,
			std::string Privatekey_File,
			std::string Publiccertificate_File,
			std::string dh_File);

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

		std::shared_ptr<WSClient> CreateClient(std::string Publiccertificate_File);
		std::shared_ptr<WSClient> CreateClient();
		void Connect(std::shared_ptr<WSClient> client, const char* host, unsigned short port);

		void set_MaxPayload(WSListener& s, unsigned long long int bytes);
		void get_MaxPayload(WSListener& s);

		void set_ReadTimeout(WSListener& s,unsigned int seconds);
		unsigned int  get_ReadTimeout(WSListener& s);
		void set_WriteTimeout(WSListener& s, unsigned int seconds);
		unsigned int  get_WriteTimeout(WSListener& s);

		void send(const std::shared_ptr<WSocket>& s, const UnpackedMessage& msg);
		bool closed(std::shared_ptr<WSocket>& s);
		std::string get_address(std::shared_ptr<WSocket>& s);
		unsigned short get_port(std::shared_ptr<WSocket>& s);
		bool is_v4(std::shared_ptr<WSocket>& s);
		bool is_v6(std::shared_ptr<WSocket>& s);
		bool is_loopback(std::shared_ptr<WSocket>& s);
	}
}

