#pragma once
#include "Protocols.h"
#include "SocketHelper.h"
#include "Logging.h"
#include "HubImpl.h"
#include "Protocols.h"

#include <string>
#include <random>
#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
	namespace WS_LITE {

		const auto  MASKSIZE = 4;

		class WebSocket :public std::enable_shared_from_this<WebSocket>
		{
		public:
			std::vector<char> IncomingBuffer;
			boost::asio::ssl::stream<boost::asio::ip::tcp::socket> Socket_;
			std::unordered_map<std::string, std::string> Header_;
			HubImpl& HubImpl_;
			SocketTypes Server;
			SocketStats SocketStats_;
			int ReadTimeout = 5;
			int WriteTimeout = 5;

			size_t ReadLen = 0;


			unsigned char _recv_fin_rsv_opcode = 0;
			unsigned char _readheaderbuffer[8];
			unsigned char _writeheaderbuffer[sizeof(char)/*type*/ + sizeof(char)/*extra*/ + sizeof(unsigned long long)/*largest size*/ + MASKSIZE/*mask*/];
			unsigned short PingBuffer = 0x001A;

			WebSocket(boost::asio::io_service& io_service, boost::asio::ssl::context& context, SocketTypes server, HubImpl& h) : Socket_(io_service, context), Server(server), HubImpl_(h) {
				memset(&SocketStats_, 0, sizeof(SocketStats_));
			}
			~WebSocket() {
				//put disconnect here  
			}
			void receivehandshake()
			{
				auto self(shared_from_this());
				readexpire_from_now(self, ReadTimeout);
				auto read_buffer(std::make_shared<boost::asio::streambuf>());

				boost::asio::async_read_until(Socket_, *read_buffer, "\r\n\r\n", [self, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
					if (!ec) {
						SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);

						std::istream stream(read_buffer.get());
						self->Header_ = Parse_Handshake("1.1", stream);

						auto write_buffer(std::make_shared<boost::asio::streambuf>());
						std::ostream handshake(write_buffer.get());
						if (Generate_Handshake(self->Header_, handshake)) {
							if (self->HubImpl_.OnHttpUpgrade) {
								self->HubImpl_.OnHttpUpgrade(self);
							}
							boost::asio::async_write(self->Socket_, *write_buffer, [self, write_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
								if (!ec) {
									SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
									self->HubImpl_.OnConnectionHandler(self);
									self->readheader();
								}
								else {
									SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket receivehandshake failed " << ec.message());
								}
							});
						}
						else {
							SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket Generate_Handshake failed " );
						}
					}
					else {
						SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake failed " << ec.message());
					}
				});
			}
			void sendHandshake()
			{

				auto self(shared_from_this());
				writeexpire_from_now(self, WriteTimeout);

				auto write_buffer(std::make_shared<boost::asio::streambuf>());

				std::ostream request(write_buffer.get());

				request << "GET / HTTP/1.1" << HTTP_ENDLINE;
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
						auto read_buffer(std::make_shared<boost::asio::streambuf>());
						boost::asio::async_read_until(self->Socket_, *read_buffer, "\r\n\r\n", [read_buffer, accept_sha1, self](const boost::system::error_code& ec, size_t bytes_transferred) {
							if (!ec) {
								writeexpire_from_now(self, 0);//make sure to reset the write timmer
								SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);
								std::istream stream(read_buffer.get());
								self->Header_ = Parse_Handshake("1.1", stream);
								if (Base64Decode(self->Header_[HTTP_SECWEBSOCKETACCEPT]) == accept_sha1) {
									self->HubImpl_.OnConnectionHandler(self, self->Header_);
									self->readheader();
								}
								else {
									SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket handshake failed "<< ec.message());
								}
							}
						});
					}
					else {
						self->close(1002, std::string("Failed sending handshake ") + ec.message());
					}
				});
			}

			void readheader()
			{
				auto self(shared_from_this());
				readexpire_from_now(self, 0);

				boost::asio::async_read(Socket_, boost::asio::const_buffer(_readheaderbuffer, 2), [self](const boost::system::error_code& ec, size_t bytes_transferred) {
					if (!ec) {
						assert(bytes_transferred == 2);
						self->ReadLen = 0;
						self->_recv_fin_rsv_opcode = self->_readheaderbuffer[0];
						//Close connection if unmasked message from client (protocol error)
						if (self->Server && self->_readheaderbuffer[1] < 128) {
							SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Closing connection because mask was not received");
						}
						else if (self->_readheaderbuffer[1] >= 128) {
							SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Closing connection because the message was masked");
						}
						auto readbytes = (self->_readheaderbuffer[1] & 127) == 126 ? 2 : ((self->_readheaderbuffer[1] & 127) == 127 ? 8 : 0);
						if (readbytes != 0) {
							boost::asio::async_read(self->Socket_, boost::asio::buffer(self->_readheaderbuffer, readbytes), [self, readbytes](const boost::system::error_code& ec, size_t bytes_transferred) {
								UNUSED(bytes_transferred);
								if (!ec) {
									assert(static_cast<size_t>(readbytes) == bytes_transferred);
									for (int c = 0; c < readbytes; c++) {
										self->ReadLen += self->_readheaderbuffer[c] << (8 * (readbytes - 1 - c));
									}
									self->readbody();
								}
								else {
									SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "readheader async_read 2 "<< ec.message());
								}
							});
						}
						else {
							self->ReadLen = self->_readheaderbuffer[1] & 127;
							self->readbody();
						}
					}
					else {
						SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "readheader async_read 1 " << ec.message());
					}
				});
			}
			void readbody()
			{

				auto self(shared_from_this());
				readexpire_from_now(self, ReadTimeout);
				ReadLen += Server ? MASKSIZE : 0;//if this is a server, it receives 4 extra bytes
				IncomingBuffer.reserve(ReadLen);

				auto p(IncomingBuffer.data());
				auto size(ReadLen);
				boost::asio::async_read(Socket_, boost::asio::const_buffer(p, size), [p, self](const boost::system::error_code& ec, size_t bytes_transferred) {

					if (!ec) {
						assert(self->ReadLen == bytes_transferred);
						//If connection close
						if (getOpCode(self->_recv_fin_rsv_opcode) == OpCode::CLOSE) {
							int status = 0;
							if (bytes_transferred >= 2) {
								unsigned char byte1 = p[0];
								unsigned char byte2 = p[1];
								status = (byte1 << 8) + byte2;
							}
							std::string msg("Close requested");
							self->close(status, msg);
						}
						else if (getOpCode(self->_recv_fin_rsv_opcode) == OpCode::PING) {//ping
							SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Ping Received");


							boost::asio::async_write(self->Socket_, boost::asio::const_buffer(&self->PingBuffer, sizeof(PingBuffer)), [self](const boost::system::error_code& ec, std::size_t)
							{
								if (ec) self->close(1002, std::string("ping send failed ") + ec.message());
								self->readheader();
							});
						}
						else {

							if (self->Server) {
								assert(bytes_transferred > 4);

								//servers receive data masked, so it needs to be unmasked
								unsigned char mask[MASKSIZE];
								memcpy(mask, packet.Payload, sizeof(mask));
								auto startpack = packet.Payload;
								std::vector<char> test;
								test.resize(packet.ReadLen - MASKSIZE);

								for (size_t c = 0; c < packet.ReadLen - MASKSIZE; c++) {
									test[c] = startpack[c] = startpack[c + MASKSIZE] ^ mask[c % MASKSIZE];
								}
							}

							memcpy(&self->_ReadPacketHeader, packet.Payload, sizeof(self->_ReadPacketHeader));
							memmove(packet.Payload, packet.Payload + sizeof(self->_ReadPacketHeader), self->_ReadPacketHeader.ReadLen);

							packet.Packet_Type = self->_ReadPacketHeader.Packet_Type;
							packet.ReadLen = self->_ReadPacketHeader.ReadLen;
							auto spac(std::make_shared<Packet>(self->decompress(packet)));

							self->_IBaseNetworkDriver->OnReceive(self, spac);
							self->readheader();
						}
					}
					else {
						self->close(std::string("readheader async_read ") + ec.message());
					}
				});
			}
		};
	}
}