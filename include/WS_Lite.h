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

		enum SocketTypes {
			SERVER,
			CLIENT
		};
		enum OpCode : unsigned char {
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
		struct SocketEvents {
			std::function<void(WSocket, std::unordered_map<std::string, std::string>&)> onConnection;
			std::function<void(WSocket, UnpackedMessage&, PackgedMessageInfo&)> onMessage;
			std::function<void(WSocket, int code, char *message, size_t length)> onDisconnection;
			std::function<void(WSocket, char *, size_t)> onPing;
			std::function<void(WSocket, char *, size_t)> onPong;
			std::function<void(WSocket)> onHttpUpgrade;

		};
		struct WS_Config {
			unsigned short Port;
		};
		struct WSS_Config:WS_Config {
			std::string Password;
			std::string Privatekey_File;
			std::string Publiccertificate_File;
			std::string dh_File;
		};
	
		std::shared_ptr<WSListener> CreateListener(const WS_Config& c, SocketEvents<WSocket>& se);
		void StartListening(std::shared_ptr<WSListener>& l);

		std::shared_ptr<WSSListener> CreateListener(const WSS_Config& c, SocketEvents<WSSocket>& se);
		void StartListening(std::shared_ptr<WSSListener>& l);

		void set_ReadTimeout(WSListener& s,unsigned int seconds);
		void set_ReadTimeout(WSSListener& s, unsigned int seconds);

		void get_ReadTimeout(WSListener& s);
		void get_ReadTimeout(WSSListener& s);
	
		void set_WriteTimeout(WSListener& s, unsigned int seconds);
		void set_WriteTimeout(WSSListener& s, unsigned int seconds);

		void get_WriteTimeout(WSListener& s);
		void get_WriteTimeout(WSSListener& s);

		void send(WSocket& s, char *, size_t);
		void send(WSSocket& s, char *, size_t);

		void close(WSocket& s, int code, std::string reason);
		void close(WSSocket& s, int code, std::string reason);

		bool closed(WSocket& s);
		bool closed(WSSocket& s);

		std::string get_address(WSocket& s);
		std::string get_address(WSSocket& s);

		unsigned short get_port(WSocket& s);
		unsigned short get_port(WSSocket& s);

		bool is_v4(WSocket& s);
		bool is_v4(WSSocket& s);

		bool is_v6(WSocket& s);
		bool is_v6(WSSocket& s);

		bool is_loopback(WSocket& s);
		bool is_loopback(WSSocket& s);
	}
}

