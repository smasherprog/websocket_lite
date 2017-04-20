#pragma once
#include "WebSocket.h"
#include "internal/WebSocketImpl.h"
#include "internal/SocketHelper.h"

namespace SL {
	namespace WS_LITE {
		void send(WebSocket * s, char * d, size_t si)
		{

		}
		void close(WebSocket * s, int code, std::string reason)
		{
			
		}
		bool closed(WebSocket * s)
		{
			return false;
		}
		SocketStats get_SocketStats(WebSocket * s)
		{
			return s->SocketStats_;
		}
		void set_ReadTimeout(WebSocket * s, int t)
		{
			s->ReadTimeout = t;
		}
		void set_WriteTimeout(WebSocket * s, int t)
		{
			s->WriteTimeout = t;
		}
		const std::unordered_map<std::string, std::string>& get_headers(WebSocket * s)
		{
			return s->Header_;
		}
		std::string get_address(WebSocket * s)
		{
			return get_address(s->Socket_);
		}
		unsigned short get_port(WebSocket * s)
		{
			return get_port(s->Socket_);
		}
		bool is_v4(WebSocket * s)
		{
			return is_v4(s->Socket_);
		}
		bool is_v6(WebSocket * s)
		{
			return is_v6(s->Socket_);
		}
		bool is_loopback(WebSocket * s)
		{
			return is_loopback(s->Socket_);
		}
	}
}