#pragma once
#include "WS_Lite.h"
#include "internal/Base64.h"
#include "internal/SHA.h"

#include <unordered_map>
#include <sstream>
#include <string>

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
		/*
		0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-------+-+-------------+-------------------------------+
		|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
		|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
		|N|V|V|V|       |S|             |   (if payload len==126/127)   |
		| |1|2|3|       |K|             |                               |
		+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
		|     Extended payload length continued, if payload len == 127  |
		+ - - - - - - - - - - - - - - - +-------------------------------+
		|                               |Masking-key, if MASK set to 1  |
		+-------------------------------+-------------------------------+
		| Masking-key (continued)       |          Payload Data         |
		+-------------------------------- - - - - - - - - - - - - - - - +
		:                     Payload Data continued ...                :
		+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
		|                     Payload Data continued ...                |
		+---------------------------------------------------------------+


		*/
		
		struct WSHeader {
			bool FIN : 1;
			bool RSV1 : 1;
			bool RSV2 : 1;
			bool RSV3 : 1;
			OpCode Opcode : 4;
			bool Mask : 1;//all frames sent from client to server should have mask data
			unsigned char Payloadlen : 7;
			union {
				unsigned short ShortPayloadlen;
				unsigned long long int ExtendedPayloadlen;
			};
		};
		auto inline GetPayloadBytes(WSHeader* buff) { return (buff->Payloadlen & 127) == 126 ? 2 : ((buff->Payloadlen & 127) == 127 ? 8 : 1); }
		template <typename T>
		T swap_endian(T u)
		{
			static_assert (CHAR_BIT == 8, "CHAR_BIT != 8");
			union
			{
				T u;
				unsigned char u8[sizeof(T)];
			} source, dest;
			source.u = u;
			for (size_t k = 0; k < sizeof(T); k++)
				dest.u8[k] = source.u8[sizeof(T) - k - 1];

			return dest.u;
		}
		std::string url_decode(const std::string& in)
		{
			std::string out;
			out.reserve(in.size());
			for (std::size_t i = 0; i < in.size(); ++i)
			{
				if (in[i] == '%')
				{
					if (i + 3 <= in.size())
					{
						int value = 0;
						std::istringstream is(in.substr(i + 1, 2));
						if (is >> std::hex >> value)
						{
							out += static_cast<char>(value);
							i += 2;
						}
						else
						{
							return std::string("/");
						}
					}
					else
					{
						return std::string("/");
					}
				}
				else if (in[i] == '+')
				{
					out += ' ';
				}
				else
				{
					out += in[i];
				}
			}
			return out;
		}

		std::unordered_map<std::string, std::string> Parse_Handshake(std::string defaultheaderversion, std::istream& stream)
		{
			std::unordered_map<std::string, std::string> header;
			std::string line;
			std::getline(stream, line);
			size_t method_end;
			if ((method_end = line.find(' ')) != std::string::npos) {
				size_t path_end;
				if ((path_end = line.find(' ', method_end + 1)) != std::string::npos) {
					header[HTTP_METHOD] = line.substr(0, method_end);
					header[HTTP_PATH] = url_decode(line.substr(method_end + 1, path_end - method_end - 1));
					if ((path_end + 6) < line.size())
						header[HTTP_VERSION] = line.substr(path_end + 6, line.size() - (path_end + 6) - 1);
					else
						header[HTTP_VERSION] = defaultheaderversion;

					getline(stream, line);
					size_t param_end;
					while ((param_end = line.find(':')) != std::string::npos) {
						size_t value_start = param_end + 1;
						if ((value_start) < line.size()) {
							if (line[value_start] == ' ')
								value_start++;
							if (value_start < line.size())
								header.insert(std::make_pair(line.substr(0, param_end), line.substr(value_start, line.size() - value_start - 1)));
						}

						getline(stream, line);
					}
				}
			}
			return header;
		}

		const std::string ws_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		bool Generate_Handshake(std::unordered_map<std::string, std::string>& header, std::ostream & stream)
		{
			auto header_it = header.find(HTTP_SECWEBSOCKETKEY);
			if (header_it == header.end())
				return false;

			auto sha1 = SHA1(header_it->second + ws_magic_string);
			stream << "HTTP/1.1 101 Web Socket Protocol Handshake" << HTTP_ENDLINE;
			stream << "Upgrade: websocket" << HTTP_ENDLINE;
			stream << "Connection: Upgrade" << HTTP_ENDLINE;
			stream << HTTP_SECWEBSOCKETACCEPT << HTTP_KEYVALUEDELIM << Base64Encode(sha1) << HTTP_ENDLINE << HTTP_ENDLINE;
			return true;
		}

	}
}