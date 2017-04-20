#pragma once
#include <unordered_map>
#include <string>
#include "Protocols.h"

namespace SL {
	namespace WS_LITE {
		class WebSocket;
		void send(WebSocket* s, char *, size_t);
		void close(WebSocket* s, int code, std::string reason);
		bool closed(WebSocket* s);

		//Get the statstics for this socket
		SocketStats get_SocketStats(WebSocket* s);

		//s in in seconds
		void set_ReadTimeout(WebSocket* s, int t);
		//s in in seconds
		void set_WriteTimeout(WebSocket* s, int t);

		const std::unordered_map<std::string, std::string>& get_headers(WebSocket* s);
		std::string get_address(WebSocket* s);
		unsigned short get_port(WebSocket* s);
		bool is_v4(WebSocket* s);
		bool is_v6(WebSocket* s);
		//is the this connection to ourselfs? i.e. 127.0.0.1 or ::1, etc
		bool is_loopback(WebSocket* s);

	}
}