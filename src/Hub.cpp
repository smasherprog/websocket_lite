#include "Hub.h"
#include "internal/WebSocket.h"

#include <thread>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
	namespace WS_LITE {



		class HubImpl : std::enable_shared_from_this<HubImpl> {
		public:

			boost::asio::ip::tcp::acceptor acceptor;
			boost::asio::io_service io_service;
			std::thread io_servicethread;
			std::unique_ptr<boost::asio::io_service::work> work;
			boost::asio::ssl::context sslcontext;
			std::string Password;

			std::function<void(std::weak_ptr<WebSocket>, HttpRequest)> OnConnectionHandler;
			std::function<void(std::weak_ptr<WebSocket>, char *, size_t, OpCode)> OnMessageHandler;
			std::function<void(std::weak_ptr<WebSocket>, int code, char *message, size_t length)> OnDisconnectHandler;
			std::function<void(std::weak_ptr<WebSocket>, char *, size_t)> OnPingHandler;
			std::function<void(std::weak_ptr<WebSocket>, char *, size_t)> OnPongHandler;

			HubImpl(const HubConfig& c) :
				Password(c.Password),
				acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), c.Port)),
				work(std::make_unique<boost::asio::io_service::work>(io_service)),
				sslcontext(boost::asio::ssl::context::tlsv11)
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
			~HubImpl() {
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
				auto self = shared_from_this();
				auto new_session = std::make_shared<WebSocket>(io_service, sslcontext, true);
				acceptor.async_accept(new_session->Socket_.lowest_layer(), [self, new_session](const boost::system::error_code& ec)
				{
					if (!ec)
					{
						new_session->Socket_.async_handshake(boost::asio::ssl::stream_base::server, [self, new_session](const boost::system::error_code& ec) {
							if (!ec) {
								new_session->Start();
							}
						});
					}
					self->Listen();
				});
			}

		};


		Hub::Hub(const HubConfig & c)
		{
			HubImpl_ = std::make_shared<HubImpl>(c);
		}

		Hub::~Hub()
		{
		}

		void Hub::onConnection(std::function<void(std::weak_ptr<WebSocket>, HttpRequest)> handler)
		{
			HubImpl_->OnConnectionHandler = handler;
		}


		void Hub::onMessage(std::function<void(std::weak_ptr<WebSocket>, char*, size_t, OpCode)> handler)
		{
			HubImpl_->OnMessageHandler = handler;
		}

		void Hub::onDisconnection(std::function<void(std::weak_ptr<WebSocket>, int code, char*message, size_t length)> handler)
		{
			HubImpl_->OnDisconnectHandler = handler;
		}

		void Hub::onPing(std::function<void(std::weak_ptr<WebSocket>, char*, size_t)> handler)
		{
			HubImpl_->OnPingHandler = handler;
		}

		void Hub::onPong(std::function<void(std::weak_ptr<WebSocket>, char*, size_t)> handler)
		{
			HubImpl_->OnPongHandler = handler;
		}

		void Hub::Run()
		{
			HubImpl_->Listen();
		}

	}
}
