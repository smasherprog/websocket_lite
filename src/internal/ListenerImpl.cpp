#include "WS_Lite.h"
#include "internal/WebSocketImpl.h"

#include <memory>
#include <thread>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
	namespace WS_LITE {

		class WS {
		public:
			WS(unsigned short port) : acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
				work(std::make_unique<boost::asio::io_service::work>(io_service)) { }
			~WS() {
				boost::system::error_code ec;
				acceptor.close(ec);
				work.reset();
				io_service.stop();
				while (!io_service.stopped()) {
					std::this_thread::sleep_for(std::chrono::milliseconds(5));
				}
				if (io_servicethread.joinable()) io_servicethread.join();
			}
			boost::asio::ip::tcp::acceptor acceptor;
			boost::asio::io_service io_service;
			std::thread io_servicethread;
			std::unique_ptr<boost::asio::io_service::work> work;
		};
		class WSS :public WS {
		public:
			WSS(unsigned short port, std::string password) : Password(password),
				sslcontext(boost::asio::ssl::context::tlsv11), WS(port)
			{ }
			~WSS() { }
			boost::asio::ssl::context sslcontext;
			std::string Password;
		};
		template<class T> class Listener {};

		template<>class Listener<WSS> : std::enable_shared_from_this<Listener<WSS>> {
		public:

			WSS WebSocket_Type;
			SocketEvents<WSSocket> SocketEvents_;
			Listener(const WSS_Config& c, SocketEvents<WSSocket>& se) :
				WebSocket_Type(c.Port, c.Password)
			{
				WebSocket_Type.sslcontext.set_options(
					boost::asio::ssl::context::default_workarounds
					| boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3
					| boost::asio::ssl::context::single_dh_use);
				boost::system::error_code ec;
				auto pass = c.Password;
				WebSocket_Type.sslcontext.set_password_callback([pass](std::size_t size, boost::asio::ssl::context::password_purpose purpose) { return pass; }, ec);
				WebSocket_Type.sslcontext.use_tmp_dh_file(c.dh_File, ec);
				WebSocket_Type.sslcontext.use_certificate_chain_file(c.Publiccertificate_File, ec);
				WebSocket_Type.sslcontext.set_default_verify_paths(ec);
				WebSocket_Type.sslcontext.use_private_key_file(c.Privatekey_File, boost::asio::ssl::context::pem, ec);
				WebSocket_Type.io_servicethread = std::thread([&]() {
					boost::system::error_code ec;
					WebSocket_Type.io_service.run(ec);
				});
			}
			~Listener() { }
			void Listen() {
				auto self = shared_from_this();
				auto new_session = std::make_shared<Socket<WSSocket>>(WebSocket_Type.io_service, WebSocket_Type.sslcontext, true);
				WebSocket_Type.acceptor.async_accept(new_session->.lowest_layer(), [self, new_session](const boost::system::error_code& ec)
				{
					if (!ec)
					{
						new_session->Socket_.async_handshake(boost::asio::ssl::stream_base::server, [self, new_session](const boost::system::error_code& ec) {
							if (!ec) {
								new_session->receivehandshake();
							}
						});
					}
					self->Listen();
				});
			}
		};

		template<>class Listener<WS> : std::enable_shared_from_this<Listener<WS>> {
		public:

			WS WebSocket_Type;
			SocketEvents<WSocket> SocketEvents_;

			Listener(const WS_Config& c, SocketEvents<WSocket> & se) :
				WebSocket_Type(c.Port)
			{
				WebSocket_Type.io_servicethread = std::thread([&]() {
					boost::system::error_code ec;
					WebSocket_Type.io_service.run(ec);
				});
			}
			~Listener() { }
			void Listen() {
				auto self = shared_from_this();
				auto new_session = std::make_shared<Socket<WSocket>>(WebSocket_Type.io_service, true);
				WebSocket_Type.acceptor.async_accept(new_session->WSocket_, [self, new_session](const boost::system::error_code& ec)
				{
					if (!ec)
					{
						new_session->receivehandshake();
					}
					self->Listen();
				});
			}
		};
		std::shared_ptr<Listener<WSS>> CreateListener(const WSS_Config & c, SocketEvents<WSSocket> & se)
		{
			return std::make_shared<Listener<WSS>>(c, se);
		}

		std::shared_ptr<Listener<WS>> CreateListener(const WS_Config & c, SocketEvents<WSocket> & se)
		{
			return std::make_shared<Listener<WS>>(c, se);
		}

		void StartListening(std::shared_ptr<Listener<WSS>>& l)
		{
			if (l) {
				l->Listen();
			}
		}
		void StartListening(std::shared_ptr<Listener<WS>>& l)
		{
			if (l) {
				l->Listen();
			}
		}
	}
}
