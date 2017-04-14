#include "WSSListiner.h"
#include "Socket.h"

#include <thread>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
	namespace WS_LITE {


		class Socket
		{
		public:
			Socket(boost::asio::io_service& io_service, boost::asio::ssl::context& context) : socket_(io_service, context)
			{
			}


			void handle_read(const boost::system::error_code& error, size_t bytes_transferred)
			{

			}

			void handle_write(const boost::system::error_code& error)
			{

			}


			boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;

		};

		void Read(Socket& s) {
			//boost::asio::async_read(s.socket_, 
		}
		void Write(Socket& s) {

		}

		class WSSListinerImpl {
		public:

			boost::asio::ip::tcp::acceptor acceptor;
			boost::asio::io_service io_service;
			std::thread io_servicethread;
			std::unique_ptr<boost::asio::io_service::work> work;
			boost::asio::ssl::context sslcontext;
			std::string Password;

			WSSListinerImpl(const WSSListenerConfig& c) :
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
				sslcontext.set_password_callback([pass] (std::size_t size, boost::asio::ssl::context::password_purpose purpose){ return pass; }, ec);
				sslcontext.use_tmp_dh_file(c.dh_File, ec);
				sslcontext.use_certificate_chain_file(c.Publiccertificate_File, ec);
				sslcontext.set_default_verify_paths(ec);
				sslcontext.use_private_key_file(c.Privatekey_File, boost::asio::ssl::context::pem, ec);
				io_servicethread = std::thread([&]() {
					boost::system::error_code ec;
					io_service.run(ec);
				});
			}
			virtual ~WSSListinerImpl() {
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
				auto new_session = new Socket(io_service, sslcontext);
				acceptor.async_accept(new_session->socket_.lowest_layer(), [this, new_session](const boost::system::error_code& ec)
				{
					if (!ec)
					{
						new_session->socket_.async_handshake(boost::asio::ssl::stream_base::server, [new_session](const boost::system::error_code& ec) {
							if (!ec) {
								Read(*new_session);
							}
							else {
								delete new_session;
							}
						});
					}
					else {
						delete new_session;
					}
					Listen();
				});
			}

		};


		WSSListiner::WSSListiner(const WSSListenerConfig & c)
		{
			WSSListinerImpl_ = std::make_unique<WSSListinerImpl>(c);
		}

		WSSListiner::~WSSListiner()
		{
		}

		void WSSListiner::Listen()
		{
			WSSListinerImpl_->Listen();
		}

	}
}
