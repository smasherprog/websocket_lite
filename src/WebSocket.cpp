#pragma once
#include "WebSocket.h"
#include "internal/WebSocketImpl.h"
#include "internal/SocketHelper.h"

namespace SL {
	namespace WS_LITE {

		void send(Socket<WSocket>& s, char *, size_t) {

		}
		void send(Socket<WSSocket>& s, char *, size_t) {

		}

		void close(Socket<WSocket>& s, int code, std::string reason) {

		}
		void close(Socket<WSSocket>& s, int code, std::string reason) {

		}

		bool closed(Socket<WSocket>& s) {

		}
		bool closed(Socket<WSSocket>& s) {

		}

		SocketStats get_SocketStats(Socket<WSocket>& s) {
			
		}
		SocketStats get_SocketStats(Socket<WSSocket>& s) {

		}

		void set_ReadTimeout(Socket<WSocket>& s, int seconds) {
		}
		void set_ReadTimeout(Socket<WSSocket>& s, int seconds) {
		}

		void set_WriteTimeout(Socket<WSocket>& s, int seconds) {
		}
		void set_WriteTimeout(Socket<WSSocket>& s, int seconds) {
		}

		const std::unordered_map<std::string, std::string>& get_headers(Socket<WSocket>& s) {
		}
		const std::unordered_map<std::string, std::string>& get_headers(Socket<WSSocket>& s) {
		}

		std::string get_address(Socket<WSocket>& s) {
		}
		std::string get_address(Socket<WSSocket>& s) {
		}

		unsigned short get_port(Socket<WSocket>& s) {
		}
		unsigned short get_port(Socket<WSSocket>& s) {
		}

		bool is_v4(Socket<WSocket>& s) {
		}
		bool is_v4(Socket<WSSocket>& s) {
		}

		bool is_v6(Socket<WSocket>& s) {
		}
		bool is_v6(Socket<WSSocket>& s) {
		}

		bool is_loopback(Socket<WSocket>& s) {
		}
		bool is_loopback(Socket<WSSocket>& s) {
		}

	}
}