#pragma once
#include <string>
#include <unordered_map>

namespace SL {
	namespace WS_LITE {
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

		std::unordered_map<std::string, std::string> Parse(std::string defaultheaderversion, std::istream& stream);

	}
}