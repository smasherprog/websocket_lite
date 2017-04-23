#pragma once
#include "WS_Lite.h"
#include "internal/WebSocketImpl.h"
#include "internal/SocketHelper.h"

namespace SL {
	namespace WS_LITE {

		void send(WSocket& s, char *, size_t) {

		}
		void send(WSSocket& s, char *, size_t) {

		}

		void close(WSocket& s, int code, std::string reason) {

		}
		void close(WSSocket& s, int code, std::string reason) {

		}

		bool closed(WSocket& s) {

		}
		bool closed(WSSocket& s) {

		}

		SocketStats get_SocketStats(WSocket& s) {
			
		}
		SocketStats get_SocketStats(WSSocket& s) {

		}

		void set_ReadTimeout(WSocket& s, int seconds) {
		}
		void set_ReadTimeout(WSSocket& s, int seconds) {
		}

		void set_WriteTimeout(WSocket& s, int seconds) {
		}
		void set_WriteTimeout(WSSocket& s, int seconds) {
		}

		const std::unordered_map<std::string, std::string>& get_headers(WSocket& s) {
		}
		const std::unordered_map<std::string, std::string>& get_headers(WSSocket& s) {
		}

		std::string get_address(WSocket& s) {
		}
		std::string get_address(WSSocket& s) {
		}

		unsigned short get_port(WSocket& s) {
		}
		unsigned short get_port(WSSocket& s) {
		}

		bool is_v4(WSocket& s) {
		}
		bool is_v4(WSSocket& s) {
		}

		bool is_v6(WSocket& s) {
		}
		bool is_v6(WSSocket& s) {
		}

		bool is_loopback(WSocket& s) {
		}
		bool is_loopback(WSSocket& s) {
		}

	}
}