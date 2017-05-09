#include "WS_Lite.h"
#include "Logging.h"
#include "internal/WebSocketProtocol.h"

#include <fstream>
#include <string>

namespace SL {
    namespace WS_LITE {

        bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx)
        {
            char subject_name[256];
            X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
            X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Verifying " << subject_name);

            return preverified;
        }
        template<class SOCKETTYPE>void ConnectHandshake(std::shared_ptr<WSClientImpl> self, SOCKETTYPE& socket) {
            auto write_buffer(std::make_shared<boost::asio::streambuf>());
            std::ostream request(write_buffer.get());
            auto accept_sha1 = Generate_Handshake(get_address(socket), request);

            boost::asio::async_write(*socket, *write_buffer, [write_buffer, accept_sha1, socket, self](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
                    auto read_buffer(std::make_shared<boost::asio::streambuf>());
                    boost::asio::async_read_until(*socket, *read_buffer, "\r\n\r\n", [read_buffer, accept_sha1, socket, self](const boost::system::error_code& ec, size_t bytes_transferred) {
                        if (!ec) {
                            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);
                            std::istream stream(read_buffer.get());
                            std::unordered_map<std::string, std::string> header;
                            Parse_Handshake("1.1", stream, header);
                            if (cppcodec::base64_rfc4648::decode<std::string>(header[HTTP_SECWEBSOCKETACCEPT]) == accept_sha1) {
                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Connected ");
                                auto websocket = std::make_shared<WSocketImpl>(self->io_service);
                                set_Socket(websocket, socket);
                                WSocket wsocket(websocket);
                                if (self->onHttpUpgrade) {
                                    self->onHttpUpgrade(wsocket);
                                }
                                if (self->onConnection) {
                                    self->onConnection(wsocket, header);
                                }
                                if (read_buffer->size() > bytes_transferred) {
                                    //check and handle case where more data is read
                                }
                                ReadHeader(self, websocket, socket);
                            }
                            else {
                                std::shared_ptr<WSocketImpl> ptr;
                                WSocket wsocket(ptr);
                                return Disconnect(self, wsocket, "WebSocket handshake failed  ");
                            }
                        }
                        else {
                            std::shared_ptr<WSocketImpl> ptr;
                            WSocket wsocket(ptr);
                            return Disconnect(self, wsocket, "async_read_until failed  " + ec.message());
                        }
                    });
                }
                else {
                    std::shared_ptr<WSocketImpl> ptr;
                    WSocket wsocket(ptr);
                    return Disconnect(self, wsocket, "Failed sending handshake" + ec.message());
                }
            });

        }
        void async_handshake(std::shared_ptr<WSClientImpl> self, std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
            ConnectHandshake(self, socket);
        }
        void async_handshake(std::shared_ptr<WSClientImpl> self, std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket) {
            socket->async_handshake(boost::asio::ssl::stream_base::client, [socket, self](const boost::system::error_code& ec) {
                if (!ec)
                {
                    ConnectHandshake(self, socket);
                }
                else {
                    std::shared_ptr<WSocketImpl> emptysocket;
                    WSocket websocket(emptysocket);
                    return Disconnect(self, websocket, "Failed async_handshake " + ec.message());
                }
            });
        }
        template<typename SOCKETCREATOR>void Connect(std::shared_ptr<WSClientImpl> self, const char* host, unsigned short port, SOCKETCREATOR&& socketcreator) {

            auto socket = socketcreator(self);
            boost::asio::ip::tcp::resolver resolver(self->io_service);
            auto portstr = std::to_string(port);
            boost::asio::ip::tcp::resolver::query query(host, portstr.c_str());
            boost::system::error_code ec;
            auto endpoint = resolver.resolve(query, ec);

            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "resolve " << ec.message());
            }
            else {
                boost::asio::async_connect(socket->lowest_layer(), endpoint, [socket, self](const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator)
                {
                    if (!ec)
                    {
                        async_handshake(self, socket);
                    }
                    else {
                        std::shared_ptr<WSocketImpl> emptysocket;
                        WSocket websocket(emptysocket);
                        Disconnect(self, websocket, "Failed async_connect " + ec.message());
                    }
                });
            }

        }

        WSClient WSClient::CreateClient(std::string Publiccertificate_File) {
            WSClient c;
            c.Impl_ = std::make_shared<WSClientImpl>(Publiccertificate_File);
            return c;
        }
        WSClient WSClient::CreateClient() {
            WSClient c;
            c.Impl_ = std::make_shared<WSClientImpl>();
            return c;
        }
        void WSClient::connect(const char* host, unsigned short port) {
            if (Impl_->sslcontext) {
                auto createsocket = [](auto c) {
                    auto socket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(c->io_service, *c->sslcontext);
                    socket->set_verify_mode(boost::asio::ssl::verify_peer);
                    socket->set_verify_callback(std::bind(&verify_certificate, std::placeholders::_1, std::placeholders::_2));
                    return socket;

                };
                Connect(Impl_, host, port, createsocket);
            }
            else {
                auto createsocket = [](auto c) {
                    return std::make_shared<boost::asio::ip::tcp::socket>(c->io_service);
                };
                Connect(Impl_, host, port, createsocket);
            }
        }

        void WSClient::onConnection(std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle) {
            Impl_->onConnection = handle;
        }
        void WSClient::onConnection(const std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle) {
            Impl_->onConnection = handle;
        }
        void WSClient::onMessage(std::function<void(WSocket&, WSReceiveMessage&)>& handle) {
            Impl_->onMessage = handle;
        }
        void WSClient::onMessage(const std::function<void(WSocket&, WSReceiveMessage&)>& handle) {
            Impl_->onMessage = handle;
        }
        void WSClient::onDisconnection(std::function<void(WSocket&, WSReceiveMessage&)>& handle) {
            Impl_->onDisconnection = handle;
        }
        void WSClient::onDisconnection(const std::function<void(WSocket&, WSReceiveMessage&)>& handle) {
            Impl_->onDisconnection = handle;
        }
        void WSClient::onPing(std::function<void(WSocket&, const char *, size_t)>& handle) {
            Impl_->onPing = handle;
        }
        void WSClient::onPing(const std::function<void(WSocket&, const char *, size_t)>& handle) {
            Impl_->onPing = handle;
        }
        void WSClient::onPong(std::function<void(WSocket&, const char *, size_t)>& handle) {
            Impl_->onPong = handle;
        }
        void WSClient::onPong(const std::function<void(WSocket&, const char *, size_t)>& handle) {
            Impl_->onPong = handle;
        }
        void WSClient::onHttpUpgrade(std::function<void(WSocket&)>& handle) {
            Impl_->onHttpUpgrade = handle;
        }
        void WSClient::onHttpUpgrade(const std::function<void(WSocket&)>& handle) {
            Impl_->onHttpUpgrade = handle;
        }
        void WSClient::set_ReadTimeout(unsigned int seconds) {
            Impl_->ReadTimeout = seconds;
        }
        unsigned int WSClient::get_ReadTimeout() {
            return  Impl_->ReadTimeout;
        }
        void WSClient::set_WriteTimeout(unsigned int seconds) {
            Impl_->WriteTimeout = seconds;
        }
        unsigned int WSClient::get_WriteTimeout() {
            return  Impl_->WriteTimeout;
        }
        void WSClient::set_MaxPayload(unsigned long long int bytes) {
            Impl_->MaxPayload = bytes;
        }
        unsigned long long int WSClient::get_MaxPayload() {
            return  Impl_->MaxPayload;
        }

        void WSClient::send(WSocket& s, WSSendMessage& msg) {
            auto self(Impl_);
            Impl_->io_service.post([s, msg, self]() {
                if (self->SendItems.empty()) {
                    self->SendItems.push_front(SendQueueItem{ s.WSocketImpl_, msg });
                    SL::WS_LITE::startwrite(self);
                }
                else {
                    self->SendItems.push_front(SendQueueItem{ s.WSocketImpl_, msg });
                }
            });
        }
        bool WSocket::is_open()
        {
            return false;
        }
        std::string WSocket::get_address() {
            if (WSocketImpl_->Socket) return SL::WS_LITE::get_address(WSocketImpl_->Socket);
            else  return SL::WS_LITE::get_address(WSocketImpl_->TLSSocket);
        }
        unsigned short WSocket::get_port()
        {
            if (WSocketImpl_->Socket) return SL::WS_LITE::get_port(WSocketImpl_->Socket);
            else  return SL::WS_LITE::get_port(WSocketImpl_->TLSSocket);
        }
        bool WSocket::is_v4()
        {
            if (WSocketImpl_->Socket) return SL::WS_LITE::is_v4(WSocketImpl_->Socket);
            else  return SL::WS_LITE::is_v4(WSocketImpl_->TLSSocket);
        }
        bool WSocket::is_v6()
        {
            if (WSocketImpl_->Socket) return SL::WS_LITE::is_v6(WSocketImpl_->Socket);
            else  return SL::WS_LITE::is_v6(WSocketImpl_->TLSSocket);
        }
        bool WSocket::is_loopback()
        {
            if (WSocketImpl_->Socket) return SL::WS_LITE::is_loopback(WSocketImpl_->Socket);
            else  return SL::WS_LITE::is_loopback(WSocketImpl_->TLSSocket);
        }
    }
}
