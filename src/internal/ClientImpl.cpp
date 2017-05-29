#include "WS_Lite.h"
#include "Logging.h"
#include "internal/WebSocketProtocol.h"

#include <fstream>
#include <string>

namespace SL {
    namespace WS_LITE {

        bool verify_certificate(bool preverified, asio::ssl::verify_context& ctx)
        {
            char subject_name[256];
            X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
            X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Verifying " << subject_name);

            return preverified;
        }


        template<class SOCKETTYPE>void ConnectHandshake(std::shared_ptr<WSClientImpl> self, SOCKETTYPE& socket, const std::string& host, const std::string& endpoint, const std::unordered_map<std::string, std::string>& extraheaders) {
            auto write_buffer(std::make_shared<asio::streambuf>());
            std::ostream request(write_buffer.get());

            request << "GET "<< endpoint<<" HTTP/1.1" << HTTP_ENDLINE;
            request << HTTP_HOST << HTTP_KEYVALUEDELIM << host << HTTP_ENDLINE;
            request << "Upgrade: websocket" << HTTP_ENDLINE;
            request << "Connection: Upgrade" << HTTP_ENDLINE;
    
            //Make random 16-byte nonce
            std::string nonce;
            nonce.resize(16);
            std::uniform_int_distribution<unsigned int> dist(0, 255);
            std::random_device rd;
            for (int c = 0; c < 16; c++) {
                nonce[c] = static_cast<unsigned char>(dist(rd));
            }

            auto nonce_base64 = Base64encode(nonce);
            request << HTTP_SECWEBSOCKETKEY << HTTP_KEYVALUEDELIM << nonce_base64 << HTTP_ENDLINE;
            request << "Sec-WebSocket-Version: 13" << HTTP_ENDLINE;
            for (auto& h : extraheaders) {
                request << h.first << HTTP_KEYVALUEDELIM << h.second << HTTP_ENDLINE;
            }
            //  request << "" << HTTP_ENDLINE;
            //  request << HTTP_SECWEBSOCKETEXTENSIONS << HTTP_KEYVALUEDELIM << PERMESSAGEDEFLATE << HTTP_ENDLINE;
            request << HTTP_ENDLINE << HTTP_ENDLINE;


            auto accept_sha1 = SHA1(nonce_base64 + ws_magic_string);

            asio::async_write(*socket, *write_buffer, [write_buffer, accept_sha1, socket, self](const std::error_code& ec, size_t bytes_transferred) {
                UNUSED(bytes_transferred);
                if (!ec) {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
                    auto read_buffer(std::make_shared<asio::streambuf>());
                    asio::async_read_until(*socket, *read_buffer, "\r\n\r\n", [read_buffer, accept_sha1, socket, self](const std::error_code& ec, size_t bytes_transferred) {
                        if (!ec) {
                            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);
                            std::istream stream(read_buffer.get());
                            std::unordered_map<std::string, std::string> header;
                            Parse_Handshake("1.1", stream, header);
                            if (Base64decode(header[HTTP_SECWEBSOCKETACCEPT]) == accept_sha1) {


                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Connected ");
                                auto websocket = std::make_shared<WSocketImpl>(self->WSContextImpl_->io_service);
                                if (header.find(PERMESSAGEDEFLATE) != header.end()) {
                                    websocket->CompressionEnabled = true;
                                }
                                set_Socket(websocket, socket);
                                WSocket wsocket(websocket);
                                if (self->onHttpUpgrade) {
                                    self->onHttpUpgrade(wsocket);
                                }
                                if (self->onConnection) {
                                    self->onConnection(wsocket, header);
                                }
                                if (read_buffer->size() > bytes_transferred) {
                                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Extra Data " << read_buffer->size() - bytes_transferred);
                                }
                                ReadHeaderStart(self, websocket, socket);
                            }
                            else {
                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket handshake failed  ");
                                std::shared_ptr<WSocketImpl> emptysocket;
                                WSocket ws(emptysocket);
                                if (self->onDisconnection) {
                                    self->onDisconnection(ws, 1002, "WebSocket handshake failed  ");
                                }
                            }
                        }
                        else {
                            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "async_read_until failed  " << ec.message());
                            std::shared_ptr<WSocketImpl> emptysocket;
                            WSocket ws(emptysocket);
                            if (self->onDisconnection) {
                                self->onDisconnection(ws, 1002, "async_read_until failed  " + ec.message());
                            }
                        }
                    });
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Failed sending handshake" << ec.message());
                    std::shared_ptr<WSocketImpl> emptysocket;
                    WSocket ws(emptysocket);
                    if (self->onDisconnection) {
                        self->onDisconnection(ws, 1002, "Failed sending handshake" + ec.message());
                    }
                }
            });

        }
        void async_handshake(std::shared_ptr<WSClientImpl> self, std::shared_ptr<asio::ip::tcp::socket> socket, const std::string& host, const std::string& endpoint, const std::unordered_map<std::string, std::string>& extraheaders) {
            ConnectHandshake(self, socket, host, endpoint, extraheaders);
        }
        void async_handshake(std::shared_ptr<WSClientImpl> self, std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket, const std::string& host, const std::string& endpoint, const std::unordered_map<std::string, std::string>& extraheaders) {
            socket->async_handshake(asio::ssl::stream_base::client, [socket, self, host, endpoint, extraheaders](const std::error_code& ec) {
                if (!ec)
                {
                    ConnectHandshake(self, socket, host, endpoint, extraheaders);
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Failed async_handshake " << ec.message());
                    std::shared_ptr<WSocketImpl> emptysocket;
                    WSocket ws(emptysocket);
                    if (self->onDisconnection) {
                        self->onDisconnection(ws, 1002, "Failed async_handshake " + ec.message());
                    }
                }
            });
        }
        template<typename SOCKETCREATOR>void Connect(std::shared_ptr<WSClientImpl> self, const std::string& host, PortNumber port, SOCKETCREATOR&& socketcreator, const std::string& endpoint, const std::unordered_map<std::string, std::string>& extraheaders) {

            auto socket = socketcreator(self);
            std::error_code ec;
            asio::ip::tcp::resolver resolver(self->WSContextImpl_->io_service);
            auto portstr = std::to_string(port.value);
            asio::ip::tcp::resolver::query query(host, portstr.c_str());

            auto resolvedendpoint = resolver.resolve(query, ec);

            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "resolve error " << ec.message());
                std::shared_ptr<WSocketImpl> emptysocket;
                WSocket ws(emptysocket);
                if (self->onDisconnection) {
                    self->onDisconnection(ws, 1002, "resolve error " + ec.message());
                }
            }
            else {
                asio::async_connect(socket->lowest_layer(), resolvedendpoint, [socket, self, host, endpoint, extraheaders](const std::error_code& ec, asio::ip::tcp::resolver::iterator)
                {
                    std::error_code e;
                    socket->lowest_layer().set_option(asio::ip::tcp::no_delay(true), e);
                    if (e) {
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "set_option error " << e.message());
                        e.clear();
                    }
                    if (!ec)
                    {
                        async_handshake(self, socket, host, endpoint, extraheaders);
                    }
                    else {
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Failed async_connect " << ec.message());
                        std::shared_ptr<WSocketImpl> emptysocket;
                        WSocket ws(emptysocket);
                        if (self->onDisconnection) {
                            self->onDisconnection(ws, 1002, "Failed async_connect " + ec.message());
                        }
                    }
                });
            }

        }

        void WSClient::connect(const std::string& host, PortNumber port, const std::string& endpoint, const std::unordered_map<std::string, std::string>& extraheaders) {
            if (Impl_->TLSEnabled) {
                auto createsocket = [](auto c) {
                    auto socket = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(c->WSContextImpl_->io_service, c->sslcontext);
                    socket->set_verify_mode(asio::ssl::verify_fail_if_no_peer_cert);
                    socket->set_verify_callback(std::bind(&verify_certificate, std::placeholders::_1, std::placeholders::_2));
                    return socket;

                };
                Connect(Impl_, host, port, createsocket, endpoint, extraheaders);
            }
            else {
                auto createsocket = [](auto c) {
                    return std::make_shared<asio::ip::tcp::socket>(c->WSContextImpl_->io_service);
                };
                Connect(Impl_, host, port, createsocket, endpoint, extraheaders);
            }
        }

        void WSClient::onConnection(std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle) {
            Impl_->onConnection = handle;
        }
        void WSClient::onConnection(const std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle) {
            Impl_->onConnection = handle;
        }
        void WSClient::onMessage(std::function<void(WSocket&, const WSMessage&)>& handle) {
            Impl_->onMessage = handle;
        }
        void WSClient::onMessage(const std::function<void(WSocket&, const WSMessage&)>& handle) {
            Impl_->onMessage = handle;
        }
        void WSClient::onDisconnection(std::function<void(WSocket&, unsigned short, const std::string&)>& handle) {
            Impl_->onDisconnection = handle;
        }
        void WSClient::onDisconnection(const std::function<void(WSocket&, unsigned short, const std::string&)>& handle) {
            Impl_->onDisconnection = handle;
        }
        void WSClient::onPing(std::function<void(WSocket&, const unsigned char *, size_t)>& handle) {
            Impl_->onPing = handle;
        }
        void WSClient::onPing(const std::function<void(WSocket&, const unsigned char *, size_t)>& handle) {
            Impl_->onPing = handle;
        }
        void WSClient::onPong(std::function<void(WSocket&, const unsigned char *, size_t)>& handle) {
            Impl_->onPong = handle;
        }
        void WSClient::onPong(const std::function<void(WSocket&, const unsigned char *, size_t)>& handle) {
            Impl_->onPong = handle;
        }
        void WSClient::onHttpUpgrade(std::function<void(WSocket&)>& handle) {
            Impl_->onHttpUpgrade = handle;
        }
        void WSClient::onHttpUpgrade(const std::function<void(WSocket&)>& handle) {
            Impl_->onHttpUpgrade = handle;
        }
        void WSClient::set_ReadTimeout(std::chrono::seconds seconds) {
            Impl_->ReadTimeout = seconds;
        }
        std::chrono::seconds WSClient::get_ReadTimeout() {
            return  Impl_->ReadTimeout;
        }
        void WSClient::set_WriteTimeout(std::chrono::seconds seconds) {
            Impl_->WriteTimeout = seconds;
        }
        std::chrono::seconds WSClient::get_WriteTimeout() {
            return  Impl_->WriteTimeout;
        }
        void WSClient::set_MaxPayload(size_t bytes) {
            Impl_->MaxPayload = bytes;
        }
        unsigned long long int WSClient::get_MaxPayload() {
            return  Impl_->MaxPayload;
        }

        void WSClient::send(const WSocket& s, WSMessage& msg, bool compressmessage) {
            sendImpl(Impl_, s.WSocketImpl_, msg, compressmessage);
        }
        void WSClient::close(const WSocket& s, unsigned short code, const std::string& msg)
        {
            closeImpl(Impl_, s.WSocketImpl_, code, msg);
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
        WSClient WSContext::CreateTLSClient(std::string Publiccertificate_File) {
            WSClient c;
            c.Impl_ = std::make_shared<WSClientImpl>(Impl_, Publiccertificate_File);
            return c;
        }
        WSClient WSContext::CreateTLSClient() {
            WSClient c;
            c.Impl_ = std::make_shared<WSClientImpl>(Impl_, true);
            return c;
        }
        WSClient WSContext::CreateClient() {
            WSClient c;
            c.Impl_ = std::make_shared<WSClientImpl>(Impl_);
            return c;
        }
    }
}
