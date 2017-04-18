#pragma once
#include "Protocols.h"
#include "ISocket.h"
#include "SocketHelper.h"
#include "SHA.h"
#include "Logging.h"
#include "Base64.h"

#include <string>
#include <random>
#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
	namespace WS_LITE {
		const std::string ws_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		class WebSocket :public ISocket, public std::enable_shared_from_this<WebSocket>
		{	
			public:
			boost::asio::ssl::stream<boost::asio::ip::tcp::socket> Socket_;
			std::unordered_map<std::string, std::string> Header_;

			SocketTypes Server;

			int ReadTimeout = 5;
			int WriteTimeout = 5;

			template<SocketTypes SOCKETTYPE>
			WebSocket(boost::asio::io_service& io_service, boost::asio::ssl::context& context, SOCKETTYPE server) : Socket_(io_service, context), Server(server)
			{

			}

			void Start() {
				if (Server) receivehandshake();
				else sendHandshake();
			}
			void receivehandshake()
			{
				auto self(shared_from_this());
				readexpire_from_now(self, ReadTimeout);

				std::shared_ptr<boost::asio::streambuf> read_buffer(new boost::asio::streambuf);

				boost::asio::async_read_until(Socket_, *read_buffer, "\r\n\r\n", [self, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
					if (!ec) {
						SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);

						std::istream stream(read_buffer.get());
						self->Header_ = Parse("1.1", stream);

						if (self->Header_.count(HTTP_SECWEBSOCKETKEY) == 0) return self->close(1002, "handshake async_read_until Sec-WebSocket-Key not present");//close socket and get out malformed
						auto write_buffer(std::make_shared<boost::asio::streambuf>());
						std::ostream handshake(write_buffer.get());

						handshake << "HTTP/1.1 101 Web Socket Protocol Handshake" << HTTP_ENDLINE;
						handshake << "Upgrade: websocket" << HTTP_ENDLINE;
						handshake << "Connection: Upgrade" << HTTP_ENDLINE;

						handshake << HTTP_SECWEBSOCKETACCEPT << HTTP_KEYVALUEDELIM << Base64Encode(SHA1(self->Header_[HTTP_SECWEBSOCKETKEY] + ws_magic_string)) << HTTP_ENDLINE << HTTP_ENDLINE;
						boost::asio::async_write(self->Socket_, *write_buffer, [self, write_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
							if (!ec) {
								SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
								self->_IBaseNetworkDriver->OnConnect(self);
								self->readheader();
							}
							else {
								self->close(1002, std::string("handshake async_write ") + ec.message());
							}
						});
					}
					else {
						self->close(1002, std::string("handshake async_read_until ") + ec.message());
					}
				});
			}
			void sendHandshake()
			{

				auto self(shared_from_this());
				writeexpire_from_now(self, WriteTimeout);

				std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);

				std::ostream request(write_buffer.get());

				request << "GET /rdpenpoint/ HTTP/1.1" << HTTP_ENDLINE;
				request << "Host: " << get_address() << HTTP_ENDLINE;
				request << "Upgrade: websocket" << HTTP_ENDLINE;
				request << "Connection: Upgrade" << HTTP_ENDLINE;

				//Make random 16-byte nonce
				std::string nonce;
				nonce.resize(16);
				std::uniform_int_distribution<unsigned short> dist(0, 255);
				std::random_device rd;
				for (int c = 0; c < 16; c++)
					nonce[c] = static_cast<unsigned char>(dist(rd));

				std::string nonce_base64 = Base64Encode(nonce);
				request << HTTP_SECWEBSOCKETKEY << HTTP_KEYVALUEDELIM << nonce_base64 << HTTP_ENDLINE;
				request << "Sec-WebSocket-Version: 13" << HTTP_ENDLINE << HTTP_ENDLINE;
				std::string accept_sha1(SHA1(nonce_base64 + ws_magic_string));

				boost::asio::async_write(Socket_, *write_buffer, [write_buffer, accept_sha1, self](const boost::system::error_code& ec, size_t bytes_transferred) {
					if (!ec) {
						SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
						std::shared_ptr<boost::asio::streambuf> read_buffer(new boost::asio::streambuf);
						boost::asio::async_read_until(self->Socket_, *read_buffer, "\r\n\r\n", [read_buffer, accept_sha1, self](const boost::system::error_code& ec, size_t bytes_transferred) {
							if (!ec) {
								writeexpire_from_now(self, 0);//make sure to reset the write timmer
								SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);
								std::istream stream(read_buffer.get());
								self->Header_ = Parse("1.1", stream);
								if (Base64Decode(self->Header_[HTTP_SECWEBSOCKETACCEPT]) == accept_sha1) {
									self->_IBaseNetworkDriver->OnConnect(self);
									self->readheader();
								}
								else {
									self->close(1002, std::string("WebSocket handshake failed ") + ec.message());
								}
							}
						});
					}
					else {
						self->close(1002, std::string("Failed sending handshake ") + ec.message());
					}
				});
			}
			void handle_read(const boost::system::error_code& error, size_t bytes_transferred)
			{

			}

			void handle_write(const boost::system::error_code& error)
			{

			}
		};
	}
}