#include "WS_Lite.h"
#include "internal/WebSocketImpl.h"

#include <unordered_map>
#include <memory>
#include <thread>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
	namespace WS_LITE {

		class WSSListener;
		template<class LISTENERTYPE, class WEBSOCKETTYPE> void readhandshake(std::shared_ptr<LISTNERTYPE> listener, std::shared_ptr<WEBSOCKETTYPE> socket) {

			readexpire_from_now(socket->Socket_, listener->WebSocket_Type.ReadTimeout);
			auto read_buffer(std::make_shared<boost::asio::streambuf>());

			boost::asio::async_read_until(socket->Socket_, *read_buffer, "\r\n\r\n", [listener, socket, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
				if (!ec) {
					SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);

					std::istream stream(read_buffer.get());
					auto header = Parse_Handshake("1.1", stream);

					auto write_buffer(std::make_shared<boost::asio::streambuf>());
					std::ostream handshake(write_buffer.get());
					if (Generate_Handshake(header, handshake)) {
						if (listener->SocketEvents_.onHttpUpgrade) {
							listener->SocketEvents_.onHttpUpgrade(socket);
						}
						//taking a copy of the header, will fix later
						boost::asio::async_write(socket->Socket_, *write_buffer, [listener, socket, header, write_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
							if (!ec) {
								SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
								if (listener->SocketEvents_.onConnection) {
									listener->SocketEvents_.onConnection(socket, header);
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
		class WSListener : std::enable_shared_from_this<WSListener> {
		public:

			unsigned int ReadTimeout = 5;
			unsigned int WriteTimeout = 5;
			boost::asio::ip::tcp::acceptor acceptor;
			boost::asio::io_service io_service;
			std::thread io_servicethread;
			std::unique_ptr<boost::asio::io_service::work> work;
			boost::asio::ssl::context sslcontext;
			SocketEvents<WSSocket> SocketEvents_;
			WSS_Config WSS_Config_;

			WSListener(const WSS_Config& c, SocketEvents<WSSocket>& se) :acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), c.Port)),
				work(std::make_unique<boost::asio::io_service::work>(io_service)),
				sslcontext(boost::asio::ssl::context::tlsv11),
				WSS_Config_(c)
			{

				sslcontext.set_options(
					boost::asio::ssl::context::default_workarounds
					| boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3
					| boost::asio::ssl::context::single_dh_use);
				boost::system::error_code ec;
				auto pass = c.Password;
				sslcontext.set_password_callback([pass](std::size_t size, boost::asio::ssl::context::password_purpose purpose) { return pass; }, ec);
				sslcontext.use_tmp_dh_file(c.dh_File, ec);
				sslcontext.use_certificate_chain_file(c.Publiccertificate_File, ec);
				sslcontext.set_default_verify_paths(ec);
				sslcontext.use_private_key_file(c.Privatekey_File, boost::asio::ssl::context::pem, ec);
				io_servicethread = std::thread([&]() {
					boost::system::error_code ec;
					io_service.run(ec);
				});
			}

			WSListener(const WS_Config& c, SocketEvents<WSSocket>& se) :acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), c.Port)),
				work(std::make_unique<boost::asio::io_service::work>(io_service)),
				sslcontext(boost::asio::ssl::context::tlsv11)
			{
				WSS_Config_.Port = c.Port;
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

			void Listen() {
				auto listener = shared_from_this();
				auto new_session = std::make_shared<WSSocket>(io_service, sslcontext, true);
				acceptor.async_accept(new_session->Socket_.lowest_layer(), [listener, new_session](const boost::system::error_code& ec)
				{
					if (!ec)
					{
						new_session->Socket_.async_handshake(boost::asio::ssl::stream_base::server, [listener, new_session](const boost::system::error_code& ec) {
							if (!ec) {
								readhandshake(listener, new_session);
							}
						});
					}
					listener->Listen();
				});
			}
		};

		class WSListener : std::enable_shared_from_this<WSListener> {
		public:

			WS WebSocket_Type;
			SocketEvents<WSocket> SocketEvents_;

			WSListener(const WS_Config& c, SocketEvents<WSocket> & se) :
				WebSocket_Type(c.Port)
			{
				WebSocket_Type.io_servicethread = std::thread([&]() {
					boost::system::error_code ec;
					WebSocket_Type.io_service.run(ec);
				});
			}
			~WSListener() { }
			void Listen() {
				auto self = shared_from_this();
				auto new_session = std::make_shared<WSocket>(WebSocket_Type.io_service, true);
				WebSocket_Type.acceptor.async_accept(new_session->Socket_, [self, new_session](const boost::system::error_code& ec)
				{
					if (!ec)
					{
						readhandshake(self, new_session);
					}
					self->Listen();
				});
			}
		};
		std::shared_ptr<WSListener> CreateListener(const WSS_Config & c, SocketEvents<WSocket> & se)
		{
			return std::make_shared<WSListener>(c, se);
		}

		std::shared_ptr<WSListener> CreateListener(const WS_Config & c, SocketEvents<WSocket> & se)
		{
			return std::make_shared<WSListener>(c, se);
		}

		void StartListening(std::shared_ptr<WSListener>& l)
		{
			if (l) {
				l->Listen();
			}
		}
		void set_ReadTimeout(WSListener& s, unsigned int seconds) {

		}
		void set_ReadTimeout(WSSListener& s, unsigned int seconds) {

		}

		void get_ReadTimeout(WSListener& s) {

		}
		void get_ReadTimeout(WSSListener& s) {

		}

		void set_WriteTimeout(WSListener& s, unsigned int seconds) {

		}
		void set_WriteTimeout(WSSListener& s, unsigned int seconds) {

		}

		void get_WriteTimeout(WSListener& s) {

		}
		void get_WriteTimeout(WSSListener& s) {

		}
	}
}
