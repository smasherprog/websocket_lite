#include "Logging.h"
#include "WS_Lite.h"
#include "internal/WebSocketProtocol.h"

#include <chrono>
#include <fstream>
#include <string>

namespace SL {
namespace WS_LITE {

    template <class SOCKETTYPE>
    void ConnectHandshake(const std::shared_ptr<WSContextImpl> self, SOCKETTYPE &socket, const std::string &host, const std::string &endpoint,
                          const std::unordered_map<std::string, std::string> &extraheaders)
    {
        auto write_buffer(std::make_shared<asio::streambuf>());
        std::ostream request(write_buffer.get());

        request << "GET " << endpoint << " HTTP/1.1" << HTTP_ENDLINE;
        request << HTTP_HOST << HTTP_KEYVALUEDELIM << host << HTTP_ENDLINE;
        request << "Upgrade: websocket" << HTTP_ENDLINE;
        request << "Connection: Upgrade" << HTTP_ENDLINE;

        // Make random 16-byte nonce
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
        for (auto &h : extraheaders) {
            request << h.first << HTTP_KEYVALUEDELIM << h.second << HTTP_ENDLINE;
        }
        //  request << "" << HTTP_ENDLINE;
        //  request << HTTP_SECWEBSOCKETEXTENSIONS << HTTP_KEYVALUEDELIM << PERMESSAGEDEFLATE << HTTP_ENDLINE;
        request << HTTP_ENDLINE << HTTP_ENDLINE;

        auto accept_sha1 = SHA1(nonce_base64 + ws_magic_string);

        asio::async_write(
            socket->Socket, *write_buffer, [write_buffer, accept_sha1, socket, self](const std::error_code &ec, size_t bytes_transferred) {
                UNUSED(bytes_transferred);
                if (!ec) {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
                    auto read_buffer(std::make_shared<asio::streambuf>());
                    asio::async_read_until(
                        socket->Socket, *read_buffer, "\r\n\r\n",
                        [read_buffer, accept_sha1, socket, self](const std::error_code &ec, size_t bytes_transferred) {
                            if (!ec) {
                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level,
                                               "Read Handshake bytes " << bytes_transferred << "  sizeof read_buffer " << read_buffer->size());

                                std::istream stream(read_buffer.get());

                                std::unordered_map<std::string, std::string> header;
                                if (Parse_ServerHandshake(stream, header) && Base64decode(header[HTTP_SECWEBSOCKETACCEPT]) == accept_sha1) {

                                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Connected ");

                                    if (header.find(PERMESSAGEDEFLATE) != header.end()) {
                                        socket->CompressionEnabled = true;
                                    }
                                    socket->SocketStatus_ = SocketStatus::CONNECTED;
                                    start_ping<false>(self, socket, std::chrono::seconds(5));
                                    if (self->onConnection) {
                                        self->onConnection(socket, header);
                                    }
                                    ReadHeaderStart<false>(self, socket, read_buffer);
                                }
                                else {
                                    socket->SocketStatus_ = SocketStatus::CLOSED;
                                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket handshake failed  ");
                                    if (self->onDisconnection) {
                                        self->onDisconnection(socket, 1002, "WebSocket handshake failed  ");
                                    }
                                }
                            }
                            else {
                                socket->SocketStatus_ = SocketStatus::CLOSED;
                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "async_read_until failed  " << ec.message());
                                if (self->onDisconnection) {
                                    self->onDisconnection(socket, 1002, "async_read_until failed  " + ec.message());
                                }
                            }
                        });
                }
                else {
                    socket->SocketStatus_ = SocketStatus::CLOSED;
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Failed sending handshake" << ec.message());
                    if (self->onDisconnection) {
                        self->onDisconnection(socket, 1002, "Failed sending handshake" + ec.message());
                    }
                }
            });
    }
    void async_handshake(const std::shared_ptr<WSContextImpl> self, std::shared_ptr<WSocket<false, asio::ip::tcp::socket>> socket,
                         const std::string &host, const std::string &endpoint, const std::unordered_map<std::string, std::string> &extraheaders)
    {
        ConnectHandshake(self, socket, host, endpoint, extraheaders);
    }
    void async_handshake(const std::shared_ptr<WSContextImpl> self, std::shared_ptr<WSocket<false, asio::ssl::stream<asio::ip::tcp::socket>>> socket,
                         const std::string &host, const std::string &endpoint, const std::unordered_map<std::string, std::string> &extraheaders)
    {
        socket->Socket.async_handshake(asio::ssl::stream_base::client, [socket, self, host, endpoint, extraheaders](const std::error_code &ec) {
            if (!ec) {
                ConnectHandshake(self, socket, host, endpoint, extraheaders);
            }
            else {
                socket->SocketStatus_ = SocketStatus::CLOSED;
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Failed async_handshake " << ec.message());
                if (self->onDisconnection) {
                    self->onDisconnection(socket, 1002, "Failed async_handshake " + ec.message());
                }
            }
        });
    }
    template <typename SOCKETCREATOR>
    void Connect(const std::shared_ptr<WSContextImpl> self, const std::string &host, PortNumber port, bool no_delay, SOCKETCREATOR &&socketcreator,
                 const std::string &endpoint, const std::unordered_map<std::string, std::string> &extraheaders)
    {

        auto socket = socketcreator(self);
        socket->SocketStatus_ = SocketStatus::CONNECTING;

        auto portstr = std::to_string(port.value);
        asio::ip::tcp::resolver::query query(host, portstr.c_str());

        auto resolver = std::make_shared<asio::ip::tcp::resolver>(socket->Socket.get_io_service());
        auto connected = std::make_shared<bool>(false);

        resolver->async_resolve(query, [socket, self, host, no_delay, endpoint, extraheaders, resolver,
                                        connected](const std::error_code &ec, asio::ip::tcp::resolver::iterator it) {
            if (*connected)
                return; // done

            asio::async_connect(
                socket->Socket.lowest_layer(), it,
                [socket, self, host, no_delay, endpoint, extraheaders, connected](const std::error_code &ec, asio::ip::tcp::resolver::iterator) {
                    *connected = true;
                    std::error_code e;
                    socket->Socket.lowest_layer().set_option(asio::ip::tcp::no_delay(no_delay), e);
                    if (e) {
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "set_option error " << e.message());
                        e.clear();
                    }
                    if (!ec) {
                        async_handshake(self, socket, host, endpoint, extraheaders);
                    }
                    else {
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Failed async_connect " << ec.message());
                        socket->SocketStatus_ = SocketStatus::CLOSED;
                        if (self->onDisconnection) {
                            self->onDisconnection(socket, 1002, "Failed async_connect " + ec.message());
                        }
                    }
                });
        });
    }

    void WSClient::set_ReadTimeout(std::chrono::seconds seconds) { Impl_->ReadTimeout = seconds; }
    std::chrono::seconds WSClient::get_ReadTimeout() { return Impl_->ReadTimeout; }
    void WSClient::set_WriteTimeout(std::chrono::seconds seconds) { Impl_->WriteTimeout = seconds; }
    std::chrono::seconds WSClient::get_WriteTimeout() { return Impl_->WriteTimeout; }
    void WSClient::set_MaxPayload(size_t bytes) { Impl_->MaxPayload = bytes; }
    size_t WSClient::get_MaxPayload() { return Impl_->MaxPayload; }

    std::shared_ptr<IWSClient_Configuration> WSClient_Configuration::onConnection(
        const std::function<void(const std::shared_ptr<IWSocket> &, const std::unordered_map<std::string, std::string> &)> &handle)
    {
        assert(!Impl_->onConnection);
        Impl_->onConnection = handle;
        return std::make_shared<WSClient_Configuration>(Impl_);
    }
    std::shared_ptr<IWSClient_Configuration>
    WSClient_Configuration::onMessage(const std::function<void(const std::shared_ptr<IWSocket> &, const WSMessage &)> &handle)
    {
        assert(!Impl_->onMessage);
        Impl_->onMessage = handle;
        return std::make_shared<WSClient_Configuration>(Impl_);
    }
    std::shared_ptr<IWSClient_Configuration>
    WSClient_Configuration::onDisconnection(const std::function<void(const std::shared_ptr<IWSocket> &, unsigned short, const std::string &)> &handle)
    {
        assert(!Impl_->onDisconnection);
        Impl_->onDisconnection = handle;
        return std::make_shared<WSClient_Configuration>(Impl_);
    }
    std::shared_ptr<IWSClient_Configuration>
    WSClient_Configuration::onPing(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle)
    {
        assert(!Impl_->onPing);
        Impl_->onPing = handle;
        return std::make_shared<WSClient_Configuration>(Impl_);
    }
    std::shared_ptr<IWSClient_Configuration>
    WSClient_Configuration::onPong(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle)
    {
        assert(!Impl_->onPong);
        Impl_->onPong = handle;
        return std::make_shared<WSClient_Configuration>(Impl_);
    }

    std::shared_ptr<IWSHub> WSClient_Configuration::connect(const std::string &host, PortNumber port, bool no_delay, const std::string &endpoint,
                                                            const std::unordered_map<std::string, std::string> &extraheaders)
    {
        if (Impl_->TLSEnabled) {
            auto createsocket = [](auto c) {
                auto &res = c->get();
                return std::make_shared<WSocket<false, asio::ssl::stream<asio::ip::tcp::socket>>>(c, res.io_service, res.context);
            };
            Connect(Impl_, host, port, no_delay, createsocket, endpoint, extraheaders);
        }
        else {
            auto createsocket = [](auto c) {
                auto &res = c->get();
                return std::make_shared<WSocket<false, asio::ip::tcp::socket>>(c, res.io_service);
            };
            Connect(Impl_, host, port, no_delay, createsocket, endpoint, extraheaders);
        }
        return std::make_shared<WSClient>(Impl_);
    }
} // namespace WS_LITE
} // namespace SL
