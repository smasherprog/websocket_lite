#include "WS_Lite.h"
#include "Logging.h"
#include "internal/WebSocketProtocol.h"

#include <fstream>
#include <string>

namespace SL {
	namespace WS_LITE {

		std::ifstream::pos_type filesize(const std::string& filename)
		{
			std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
			return in.tellg();
		}

		class WSClient : public WSContext, std::enable_shared_from_this<WSClient> {
		public:


			WSClient(std::string Publiccertificate_File)
			{
				sslcontext = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv11);
				std::ifstream file(Publiccertificate_File, std::ios::binary);
				assert(file);
				std::vector<char> buf;
				buf.resize(static_cast<size_t>(filesize(Publiccertificate_File)));
				file.read(buf.data(), buf.size());
				boost::asio::const_buffer cert(buf.data(), buf.size());
				boost::system::error_code ec;
				sslcontext->add_certificate_authority(cert, ec);
				ec.clear();
				sslcontext->set_default_verify_paths(ec);

			}

			WSClient()
			{
			}

			~WSClient() {

			}
			void Connect(const char* host, unsigned short port) {
				auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_service);

				boost::asio::ip::tcp::resolver resolver(io_service);
				auto portstr = std::to_string(port);
				boost::asio::ip::tcp::resolver::query query(host, portstr.c_str());
				boost::system::error_code ec;
				auto endpoint = resolver.resolve(query, ec);
				if (ec) {
					SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "resolve " << ec.message());
				}
				else {
					boost::asio::async_connect(*socket, endpoint, [socket](const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator)
					{
						if (!ec)
						{
							//sock->start();
						}
						else {
							SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "async_connect " << ec.message());
						}
					});
				}

			}
			void ConnectTLS(const char* host, unsigned short port) {

				auto socket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_service, *sslcontext);
				boost::asio::ip::tcp::resolver resolver(io_service);
				auto portstr = std::to_string(port);
				boost::asio::ip::tcp::resolver::query query(host, portstr.c_str());
				boost::system::error_code ec;
				auto endpoint = resolver.resolve(query, ec);

				if (ec) {
					SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "resolve " << ec.message());
				}
				else {
					socket->set_verify_mode(boost::asio::ssl::verify_peer);
					socket->set_verify_callback(std::bind(&WSClient::verify_certificate, this, std::placeholders::_1, std::placeholders::_2));
					boost::asio::async_connect(socket->lowest_layer(), endpoint, [socket](const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator)
					{
						if (!ec)
						{
							socket->async_handshake(boost::asio::ssl::stream_base::client, [socket](const boost::system::error_code& ec) {
								if (!ec)
								{
									//sock->start();
								}
								else {
									SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "async_handshake " << ec.message());
								}
							});
						}
						else {
							SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "async_connect " << ec.message());
						}
					});
				}

			}
			bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx)
			{
				char subject_name[256];
				X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
				X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
				SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Verifying " << subject_name);

				return preverified;
			}

		};
		std::shared_ptr<WSClient> CreateClient(std::string Publiccertificate_File) {
			return std::make_shared<WSClient>(Publiccertificate_File);
		}
		std::shared_ptr<WSClient> CreateClient() {
			return std::make_shared<WSClient>();
		}
		void Connect(std::shared_ptr<WSClient> client, const char* host, unsigned short port) {
			if (client) {
				if (client->sslcontext) {
					client->ConnectTLS(host, port);
				}
				else {
					client->Connect(host, port);
				}

			}
		}

		void onConnection(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle) {
			if (l) {
				l->onConnection = handle;
			}
		}
		void onConnection(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle) {
			if (l) {
				l->onConnection = handle;
			}
		}
		void onMessage(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)>& handle) {
			if (l) {
				l->onMessage = handle;
			}
		}
		void onMessage(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)>& handle) {
			if (l) {
				l->onMessage = handle;
			}
		}

		void onDisconnection(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, int code, char *message, size_t length)>& handle) {
			if (l) {
				l->onDisconnection = handle;
			}
		}
		void onDisconnection(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, int code, char *message, size_t length)>& handle) {
			if (l) {
				l->onDisconnection = handle;
			}
		}

		void onPing(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
			if (l) {
				l->onPing = handle;
			}
		}
		void onPing(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
			if (l) {
				l->onPing = handle;
			}
		}

		void onPong(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
			if (l) {
				l->onPong = handle;
			}
		}
		void onPong(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
			if (l) {
				l->onPong = handle;
			}
		}

		void onHttpUpgrade(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>)>& handle) {
			if (l) {
				l->onHttpUpgrade = handle;
			}
		}
		void onHttpUpgrade(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>)>& handle) {
			if (l) {
				l->onHttpUpgrade = handle;
			}
		}

		void set_ReadTimeout(WSClient& s, unsigned int seconds) {
			s.ReadTimeout = seconds;
		}

		unsigned int get_ReadTimeout(WSClient& s) {
			return s.ReadTimeout;
		}

		void set_WriteTimeout(WSClient& s, unsigned int seconds) {
			s.WriteTimeout = seconds;
		}

		unsigned int get_WriteTimeout(WSClient& s) {
			return s.WriteTimeout;
		}
		void set_MaxPayload(WSClient& s, unsigned long long int bytes) {
			s.MaxPayload = bytes;
		}
		unsigned long long int get_MaxPayload(WSClient& s) {
			return s.MaxPayload;
		}
		void send(WSocket& s, const UnpackedMessage& msg) {

		}
		bool is_open(WSocket& s) {
			if (s.Socket) {
				return s.Socket->is_open();
			}
			else {
				return s.TLSSocket->lowest_layer().is_open();
			}
		}
		std::string get_address(WSocket& s) {
			if (s.Socket) {
				return get_address(*s.Socket);
			}
			else {
				return get_address(*s.TLSSocket);
			}
		}
		unsigned short get_port(WSocket& s) {
			if (s.Socket) {
				return get_port(*s.Socket);
			}
			else {
				return get_port(*s.TLSSocket);
			}
		}
		bool is_v4(WSocket& s) {
			if (s.Socket) {
				return is_v4(*s.Socket);
			}
			else {
				return is_v4(*s.TLSSocket);
			}
		}
		bool is_v6(WSocket& s) {
			if (s.Socket) {
				return is_v6(*s.Socket);
			}
			else {
				return is_v6(*s.TLSSocket);
			}
		}
		bool is_loopback(WSocket& s) {
			if (s.Socket) {
				return is_loopback(*s.Socket);
			}
			else {
				return is_loopback(*s.TLSSocket);
			}
		}
	}
}
