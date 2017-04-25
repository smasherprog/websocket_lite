#include "WS_Lite.h"
#include "Logging.h"
#include "internal/WebSocketProtocol.h"

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
			else return -1;
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
				SL_RAT_LOG(Utilities::Logging_Levels::ERROR_log_level, ec.message());
			}
			else if (seconds >= 0) {
				self->read_deadline.async_wait([self, seconds](const boost::system::error_code& ec) {
					if (ec != boost::asio::error::operation_aborted) {
						self->close("read timer expired. Time waited: ");
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
				SL_RAT_LOG(Utilities::Logging_Levels::ERROR_log_level, ec.message());
			}
			else if (seconds >= 0) {
				self->write_deadline.async_wait([self, seconds](const boost::system::error_code& ec) {
					if (ec != boost::asio::error::operation_aborted) {
						//close("write timer expired. Time waited: " + std::to_string(seconds));
						self->close("write timer expired. Time waited: ");
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


		class WSListener : std::enable_shared_from_this<WSListener> {
		public:

			unsigned int ReadTimeout = 5;
			unsigned int WriteTimeout = 5;
			unsigned long long int MaxPayload = 1024 * 1024 * 100;//100 MBs

			boost::asio::ip::tcp::acceptor acceptor;
			boost::asio::io_service io_service;
			std::thread io_servicethread;
			std::unique_ptr<boost::asio::io_service::work> work;
			boost::asio::ssl::context sslcontext;

			std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)> onConnection;
			std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)> onMessage;
			std::function<void(std::weak_ptr<WSocket>, int code, char *message, size_t length)> onDisconnection;
			std::function<void(std::weak_ptr<WSocket>, char *, size_t)> onPing;
			std::function<void(std::weak_ptr<WSocket>, char *, size_t)> onPong;
			std::function<void(std::weak_ptr<WSocket>)> onHttpUpgrade;

			std::shared_ptr<WSS_Config> WSS_Config_;

			WSListener(unsigned short port, std::shared_ptr<WSS_Config> config) :acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
				work(std::make_unique<boost::asio::io_service::work>(io_service)),
				sslcontext(boost::asio::ssl::context::tlsv11),
				WSS_Config_(config)
			{

				sslcontext.set_options(
					boost::asio::ssl::context::default_workarounds
					| boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3
					| boost::asio::ssl::context::single_dh_use);
				boost::system::error_code ec;
				sslcontext.set_password_callback([config](std::size_t size, boost::asio::ssl::context::password_purpose) { return config->Password; }, ec);
				sslcontext.use_tmp_dh_file(WSS_Config_->dh_File, ec);
				sslcontext.use_certificate_chain_file(WSS_Config_->Publiccertificate_File, ec);
				sslcontext.set_default_verify_paths(ec);
				sslcontext.use_private_key_file(WSS_Config_->Privatekey_File, boost::asio::ssl::context::pem, ec);
				io_servicethread = std::thread([&]() {
					boost::system::error_code ec;
					io_service.run(ec);
				});
			}

			WSListener(unsigned short port) :acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
				work(std::make_unique<boost::asio::io_service::work>(io_service)),
				sslcontext(boost::asio::ssl::context::tlsv11)
			{
				io_servicethread = std::thread([&]() {
					boost::system::error_code ec;
					io_service.run(ec);
				});
			}

			~WSListener() {

				boost::system::error_code ec;
				acceptor.close(ec);
				work.reset();
				io_service.stop();
				while (!io_service.stopped()) {
					std::this_thread::sleep_for(std::chrono::milliseconds(5));
				}
				if (io_servicethread.joinable()) io_servicethread.join();


			}
			void ReadBody(std::shared_ptr<WSListener> listener, std::shared_ptr<WSocket> websocket, std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket, std::shared_ptr<WSHeader> header) {

				readexpire_from_now(websocket, ReadTimeout);
				unsigned long long int size = 0;
				switch (GetPayloadBytes(header.get())) {
				case 1:
					size = static_cast<unsigned long long int>(header->Payloadlen);
					break;
				case 2:
					size = static_cast<unsigned long long int>(swap_endian(header->ShortPayloadlen));
					break;
				case 8:
					size = static_cast<unsigned long long int>(swap_endian(header->ExtendedPayloadlen));
					break;
				default:
					SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Incorrect Payload size received ");
					return;
				}

				auto buffer = std::make_shared<char>(new char[size], [](char * p) { delete[] p; });
				if ((header->Opcode == OpCode::PING || header->Opcode == OpCode::PONG || header->Opcode == OpCode::CLOSE) && size > 125) {
					SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Payload exceeded for control frames. Size requested " << size);
					return;
				}
				size += 4;
				if (size > MaxPayload) {
					SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Payload exceeded MaxPayload size ");
					return;
				}

				boost::asio::async_read(*socket, boost::asio::buffer(buffer.get(), size), [listener, websocket, socket, header, buffer, size](const boost::system::error_code& ec, size_t bytes_transferred) {
					if (!ec) {
						if (size != bytes_transferred) {
							SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "size != bytes_transferred");
							return;
						}
						else if (header->Opcode == OpCode::PING) {
							if (listener->onPing) {
								listener->onPing(websocket, buffer.get() + 4, size - 4);
							}
							send(websocket, UnpackedMessage{ buffer.get() + 4, size - 4, OpCode::PONG });
						}
						else if (header->Opcode == OpCode::PONG) {
							if (listener->onPong) {
								listener->onPong(websocket, buffer.get() + 4, size - 4);
							}
						}
						else {
							unsigned char mask[4];
							memcpy(mask, buffer.get(), 4);
							auto p = buffer.get() + 4;
							for (decltype(size) c = 0; c < size - 4; c++) {
								p[c] = p[c] ^ mask[c % 4];
							}

						}
					}
					else {
						SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadBody " << ec.message());
					}
				});
			}
			void ReadHeader(std::shared_ptr<WSListener> listener, std::shared_ptr<WSocket> websocket, std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket) {
				readexpire_from_now(websocket, 0);
				auto buff = std::make_shared<WSHeader>();
				boost::asio::async_read(*socket, boost::asio::const_buffer(buff.get(), 2), [listener, websocket, socket, buff](const boost::system::error_code& ec, size_t bytes_transferred) {
					if (!ec) {
						assert(bytes_transferred == 2);
						if (!buff->Mask) {//Close connection if unmasked message from client (protocol error)
							SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Closing connection because mask was not received ");
						}
						else {
							auto readbytes = GetPayloadBytes(buff.get());
							if (readbytes > 1) {
								boost::asio::async_read(*socket, boost::asio::const_buffer(&buff->ExtendedPayloadlen, readbytes), [listener, websocket, socket, buff, readbytes](const boost::system::error_code& ec, size_t bytes_transferred) {
									if (readbytes != bytes_transferred) {
										SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "readbytes != bytes_transferred ");
									}
									else if (!ec) {
										listener->ReadBody(listener, websocket, socket, buff);
									}
									else {
										SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "readheader ExtendedPayloadlen " << ec.message());
									}
								});
							}
							else {
								listener->ReadBody(listener, websocket, socket, buff);
							}
						}
					}
					else {
						SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadHeader Failed: " << ec.message());
					}
				});
			}

			void TLSListen() {
				auto listener = shared_from_this();

				auto socket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_service, sslcontext);
				acceptor.async_accept(socket->lowest_layer(), [listener, socket](const boost::system::error_code& ec)
				{
					if (!ec)
					{
						socket->async_handshake(boost::asio::ssl::stream_base::server, [listener, socket](const boost::system::error_code& ec) {
							if (!ec) {
								auto read_buffer(std::make_shared<boost::asio::streambuf>());
								boost::asio::async_read_until(*socket, *read_buffer, "\r\n\r\n", [listener, socket, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
									if (!ec) {
										SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);

										std::istream stream(read_buffer.get());
										auto header = Parse_Handshake("1.1", stream);

										auto write_buffer(std::make_shared<boost::asio::streambuf>());
										std::ostream handshake(write_buffer.get());
										if (Generate_Handshake(header, handshake)) {
											auto websocket = std::make_shared<WSocket>(listener->io_service);
											websocket->TLSSocket = socket;
											if (listener->onHttpUpgrade) {
												listener->onHttpUpgrade(websocket);
											}

											boost::asio::async_write(websocket->TLSSocket, *write_buffer, [listener, websocket, socket, header, write_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
												if (!ec) {
													SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
													if (listener->onConnection) {
														listener->onConnection(websocket, header);
													}
													listener->ReadHeader(listener, websocket, socket);
												}
												else {
													SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket receivehandshake failed " << ec.message());
												}
											});
										}
										else {
											SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket Generate_Handshake failed ");
										}
									}
									else {
										SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake failed " << ec.message());
									}
								});
							}
						});
					}
					listener->TLSListen();
				});


			}
			void Listen() {
				auto listener = shared_from_this();
				auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_service);
				acceptor.async_accept(*socket, [listener, socket](const boost::system::error_code& ec)
				{
					if (!ec)
					{

						auto read_buffer(std::make_shared<boost::asio::streambuf>());
						boost::asio::async_read_until(*socket, *read_buffer, "\r\n\r\n", [listener, socket, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
							if (!ec) {
								SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);

								std::istream stream(read_buffer.get());
								auto header = Parse_Handshake("1.1", stream);

								auto write_buffer(std::make_shared<boost::asio::streambuf>());
								std::ostream handshake(write_buffer.get());
								if (Generate_Handshake(header, handshake)) {
									auto websocket = std::make_shared<WSocket>(listener->io_service);

									if (listener->onHttpUpgrade) {
										listener->onHttpUpgrade(websocket);
									}
									//taking a copy of the header, will fix later
									boost::asio::async_write(websocket->Socket, *write_buffer, [listener, websocket, header, write_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
										if (!ec) {
											SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
											if (listener->onConnection) {
												listener->onConnection(websocket, header);
											}
											//self->readheader();
										}
										else {
											SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket receivehandshake failed " << ec.message());
										}
									});
								}
								else {
									SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket Generate_Handshake failed ");
								}
							}
							else {
								SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake failed " << ec.message());
							}
						});
					}
					listener->Listen();
				});

			}
		};

		std::shared_ptr<WSListener> CreateListener(unsigned short port)
		{
			return std::make_shared<WSListener>(port);
		}

		std::shared_ptr<WSListener> CreateListener(unsigned short port, const WSS_Config& c)
		{
			auto config = std::make_shared<WSS_Config>();
			*config = c;
			return std::make_shared<WSListener>(port, config);
		}
		void StartListening(std::shared_ptr<WSListener>& l)
		{
			if (l) {
				if (l->WSS_Config_) {
					l->TLSListen();
				}
				else
				{
					l->Listen();
				}
			}
		}
		void onConnection(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle) {
			if (l) {
				l->onConnection = handle;
			}
		}
		void onConnection(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle) {
			if (l) {
				l->onConnection = handle;
			}
		}
		void onMessage(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)>& handle) {
			if (l) {
				l->onMessage = handle;
			}
		}
		void onMessage(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)>& handle) {
			if (l) {
				l->onMessage = handle;
			}
		}

		void onDisconnection(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, int code, char *message, size_t length)>& handle) {
			if (l) {
				l->onDisconnection = handle;
			}
		}
		void onDisconnection(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, int code, char *message, size_t length)>& handle) {
			if (l) {
				l->onDisconnection = handle;
			}
		}

		void onPing(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
			if (l) {
				l->onPing = handle;
			}
		}
		void onPing(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
			if (l) {
				l->onPing = handle;
			}
		}

		void onPong(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
			if (l) {
				l->onPong = handle;
			}
		}
		void onPong(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
			if (l) {
				l->onPong = handle;
			}
		}

		void onHttpUpgrade(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>)>& handle) {
			if (l) {
				l->onHttpUpgrade = handle;
			}
		}
		void onHttpUpgrade(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>)>& handle) {
			if (l) {
				l->onHttpUpgrade = handle;
			}
		}

		void set_ReadTimeout(WSListener& s, unsigned int seconds) {

		}

		void get_ReadTimeout(WSListener& s) {

		}

		void set_WriteTimeout(WSListener& s, unsigned int seconds) {

		}

		void get_WriteTimeout(WSListener& s) {

		}

	}
}
