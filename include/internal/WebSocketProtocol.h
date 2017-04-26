#pragma once
#include "WS_Lite.h"
#include "internal/Base64.h"
#include "internal/SHA.h"

#include <unordered_map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <memory>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
	namespace WS_LITE {


		template<class T>std::string get_address(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.address().to_string();
			else return "";
		}
		template<class T> unsigned short get_port(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.port();
			else return static_cast<unsigned short>(-1);
		}
		template<class T> bool is_v4(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.address().is_v4();
			else return true;
		}
		template<class T> bool is_v6(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.address().is_v6();
			else return true;
		}
		template<class T> bool is_loopback(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.address().is_loopback();
			else return true;
		}

		template<class T> void readexpire_from_now(T& self, int seconds)
		{
			boost::system::error_code ec;
			if (seconds <= 0) self->read_deadline.expires_at(boost::posix_time::pos_infin, ec);
			else  self->read_deadline.expires_from_now(boost::posix_time::seconds(seconds), ec);
			if (ec) {
				SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
			}
			else if (seconds >= 0) {
				self->read_deadline.async_wait([self, seconds](const boost::system::error_code& ec) {
					if (ec != boost::asio::error::operation_aborted) {
						//self->close("read timer expired. Time waited: ");
					}
				});
			}
		}
		template<class T> void writeexpire_from_now(T& self, int seconds)
		{
			boost::system::error_code ec;
			if (seconds <= 0) self->write_deadline.expires_at(boost::posix_time::pos_infin, ec);
			else self->write_deadline.expires_from_now(boost::posix_time::seconds(seconds), ec);
			if (ec) {
				SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
			}
			else if (seconds >= 0) {
				self->write_deadline.async_wait([self, seconds](const boost::system::error_code& ec) {
					if (ec != boost::asio::error::operation_aborted) {
						//close("write timer expired. Time waited: " + std::to_string(seconds));
						//self->close("write timer expired. Time waited: ");
					}
				});
			}
		}

		struct WSocket
		{
			WSocket(boost::asio::io_service& s) :read_deadline(s), write_deadline(s) {}
			~WSocket() {
				read_deadline.cancel();
				write_deadline.cancel();
			}
			boost::asio::deadline_timer read_deadline;
			boost::asio::deadline_timer write_deadline;
			std::shared_ptr<boost::asio::ip::tcp::socket> Socket;
			std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> TLSSocket;

		};

		struct WSContext{
			WSContext() : 
				work(std::make_unique<boost::asio::io_service::work>(io_service)) {
				io_servicethread = std::thread([&]() {
					boost::system::error_code ec;
					io_service.run(ec);
				});
			
			}
			~WSContext() {
				work.reset();
				io_service.stop();
				while (!io_service.stopped()) {
					std::this_thread::sleep_for(std::chrono::milliseconds(5));
				}
				if (io_servicethread.joinable()) io_servicethread.join();
			}
			unsigned int ReadTimeout = 5;
			unsigned int WriteTimeout = 5;
			unsigned long long int MaxPayload = 1024 * 1024 * 100;//100 MBs

			boost::asio::io_service io_service;
			std::thread io_servicethread;
			std::unique_ptr<boost::asio::io_service::work> work;
			std::unique_ptr<boost::asio::ssl::context> sslcontext;

			std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)> onConnection;
			std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)> onMessage;
			std::function<void(std::weak_ptr<WSocket>, int code, char *message, size_t length)> onDisconnection;
			std::function<void(std::weak_ptr<WSocket>, char *, size_t)> onPing;
			std::function<void(std::weak_ptr<WSocket>, char *, size_t)> onPong;
			std::function<void(std::weak_ptr<WSocket>)> onHttpUpgrade;

		};
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
		size_t inline GetPayloadBytes(WSHeader* buff) { return (buff->Payloadlen & 127) == 126 ? 2 : ((buff->Payloadlen & 127) == 127 ? 8 : 1); }
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
		inline std::string url_decode(const std::string& in)
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

		inline std::unordered_map<std::string, std::string> Parse_Handshake(std::string defaultheaderversion, std::istream& stream)
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
		inline bool Generate_Handshake(std::unordered_map<std::string, std::string>& header, std::ostream & stream)
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