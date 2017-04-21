#pragma once
#include <memory>
#include <string>
#include <functional>
#include <unordered_map>

namespace SL {
	namespace WS_LITE {
		//forward declares
		class WSocket;
		class WSSocket;
		template<class WSocket>
		class Socket<WSocket>;
		template<class WSSocket>
		class Socket<WSSocket>;

		class WS;
		class WSS;
		template <class WS>
		class Listener<WS>;
		template <class WSS>
		class Listener<WSS>;


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
		struct SocketStats {
			//total bytes that the Socket layer received from the upper layer. This is not the actual amount of data send across the network due to compressoin
			long long TotalBytesSent;
			//total bytes that the Socket layer seent to the network layer
			long long NetworkBytesSent;
			//total number of messages sent
			long long TotalMessagesSent;
			//total bytes that the upper layer received from the socket layer after decompression
			long long TotalBytesReceived;
			//total bytes that the Socket layer received from the network layer
			long long NetworkBytesReceived;
			//total number of messages received
			long long TotalMessageReceived;

		};
	
		template<class T>struct SocketEvents {
			std::function<void(std::weak_ptr<Socket<T>>)> onConnection;
			std::function<void(std::weak_ptr<Socket<T>>, char *, size_t, OpCode)> onMessage;
			std::function<void(std::weak_ptr<Socket<T>>, int code, char *message, size_t length)> onDisconnection;
			std::function<void(std::weak_ptr<Socket<T>>, char *, size_t)> onPing;
			std::function<void(std::weak_ptr<Socket<T>>, char *, size_t)> onPong;
			std::function<void(std::weak_ptr<Socket<T>>)> onHttpUpgrade;

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
	
		std::shared_ptr<Listener<WS>> CreateListener(const WS_Config& c, SocketEvents<WSocket>& se);
		void StartListening(std::shared_ptr<Listener<WS>>& l);

		std::shared_ptr<Listener<WSS>> CreateListener(const WSS_Config& c, SocketEvents<WSSocket>& se);
		void StartListening(std::shared_ptr<Listener<WSS>>& l);

		void send(Socket<WSocket>& s, char *, size_t);
		void send(Socket<WSSocket>& s, char *, size_t);

		void close(Socket<WSocket>& s, int code, std::string reason);
		void close(Socket<WSSocket>& s, int code, std::string reason);

		bool closed(Socket<WSocket>& s);
		bool closed(Socket<WSSocket>& s);

		SocketStats get_SocketStats(Socket<WSocket>& s);
		SocketStats get_SocketStats(Socket<WSSocket>& s);

		void set_ReadTimeout(Socket<WSocket>& s, int seconds);
		void set_ReadTimeout(Socket<WSSocket>& s, int seconds);

		void set_WriteTimeout(Socket<WSocket>& s, int seconds);
		void set_WriteTimeout(Socket<WSSocket>& s, int seconds);

		const std::unordered_map<std::string, std::string>& get_headers(Socket<WSocket>& s);
		const std::unordered_map<std::string, std::string>& get_headers(Socket<WSSocket>& s);

		std::string get_address(Socket<WSocket>& s);
		std::string get_address(Socket<WSSocket>& s);

		unsigned short get_port(Socket<WSocket>& s);
		unsigned short get_port(Socket<WSSocket>& s);

		bool is_v4(Socket<WSocket>& s);
		bool is_v4(Socket<WSSocket>& s);

		bool is_v6(Socket<WSocket>& s);
		bool is_v6(Socket<WSSocket>& s);

		bool is_loopback(Socket<WSocket>& s);
		bool is_loopback(Socket<WSSocket>& s);
	}
}

