#include "Logging.h"
#include "WS_Lite.h"
#include "internal/HeaderParser.h"
#include "internal/HubContext.h"
#include "internal/WebSocket.h"
#include "internal/WebSocketProtocol.h"
#if WIN32
#include <SDKDDKVer.h>
#endif
#include "asio.hpp"
#include "asio/ssl.hpp"
namespace SL {
namespace WS_LITE {

    struct HandshakeContainer {
        asio::streambuf Read;
        std::string Write;
        HttpHeader Header;
    };

    template <class SOCKETTYPE> void read_handshake(const std::shared_ptr<HubContext> listener, const SOCKETTYPE &socket)
    {
        auto handshakecontainer(std::make_shared<HandshakeContainer>());
        asio::async_read_until(
            socket->Socket, handshakecontainer->Read, "\r\n\r\n",
            [listener, socket, handshakecontainer](const std::error_code &ec, size_t bytes_transferred) {
                UNUSED(bytes_transferred);
                if (!ec) {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);

                    handshakecontainer->Header = ParseHeader(asio::buffer_cast<const char *>(handshakecontainer->Read.data()));

                    if (auto[response, parsesuccess] = CreateHandShake(handshakecontainer->Header); parsesuccess) {
                        handshakecontainer->Write = response;
                        if (socket->Parent->ExtensionOptions_ != ExtensionOptions::NO_OPTIONS) {
                            auto[headerresponse, agreedcompression] = CreateExtensionOffer(handshakecontainer->Header);
                            handshakecontainer->Write += headerresponse;
                            socket->ExtensionOption = agreedcompression;
                        }
                        handshakecontainer->Write += "\r\n";

                        asio::async_write(socket->Socket, asio::buffer(handshakecontainer->Write.data(), handshakecontainer->Write.size()),
                                          [listener, socket, handshakecontainer](const std::error_code &ec, size_t bytes_transferred) {
                                              UNUSED(bytes_transferred);
                                              if (!ec) {
                                                  SL_WS_LITE_LOG(Logging_Levels::INFO_log_level,
                                                                 "Connected: Sent Handshake bytes " << bytes_transferred);

                                                  socket->SocketStatus_ = SocketStatus::CONNECTED;
                                                  if (socket->Parent->onConnection) {
                                                      socket->Parent->onConnection(socket, handshakecontainer->Header);
                                                  }
                                                  auto bufptr = std::make_shared<asio::streambuf>();
                                                  ReadHeaderStart<true>(socket, bufptr);
                                                  start_ping<true>(socket, std::chrono::seconds(5));
                                              }
                                              else {
                                                  socket->SocketStatus_ = SocketStatus::CLOSED;
                                                  SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket receivehandshake failed " + ec.message());
                                              }
                                          });
                    }
                    else {
                        socket->SocketStatus_ = SocketStatus::CLOSED;
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket Generate_Handshake failed ");
                    }
                }
                else {
                    socket->SocketStatus_ = SocketStatus::CLOSED;
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake failed " + ec.message());
                }
            });
    }

    void async_handshake(const std::shared_ptr<HubContext> listener, const std::shared_ptr<WebSocket<true, asio::ip::tcp::socket>> socket)
    {
        read_handshake(listener, socket);
    }
    void async_handshake(const std::shared_ptr<HubContext> listener,
                         const std::shared_ptr<WebSocket<true, asio::ssl::stream<asio::ip::tcp::socket>>> socket)
    {
        socket->Socket.async_handshake(asio::ssl::stream_base::server, [listener, socket](const std::error_code &ec) {
            if (!ec) {
                read_handshake(listener, socket);
            }
            else {
                socket->SocketStatus_ = SocketStatus::CLOSED;
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "async_handshake failed " << ec.message());
            }
        });
    }

    template <typename SOCKETCREATOR>
    void Listen(const std::shared_ptr<HubContext> &listener, SOCKETCREATOR &&socketcreator, bool no_delay, bool reuse_address)
    {
        auto res = listener->getnextContext();
        auto socket = socketcreator(res);
        socket->SocketStatus_ = SocketStatus::CONNECTING;
        listener->acceptor->async_accept(socket->Socket.lowest_layer(),
                                         [listener, socket, socketcreator, no_delay, reuse_address](const std::error_code &ec) {
                                             std::error_code e;
                                             socket->Socket.lowest_layer().set_option(asio::socket_base::reuse_address(reuse_address), e);
                                             if (e) {
                                                 SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "set_option reuse_address error " << e.message());
                                                 e.clear();
                                             }
                                             socket->Socket.lowest_layer().set_option(asio::ip::tcp::no_delay(no_delay), e);
                                             if (e) {
                                                 SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "set_option no_delay error " << e.message());
                                                 e.clear();
                                             }
                                             if (!ec) {
                                                 async_handshake(listener, socket);
                                             }
                                             else {
                                                 socket->SocketStatus_ = SocketStatus::CLOSED;
                                             }
                                             Listen(listener, socketcreator, no_delay, reuse_address);
                                         });
    }

    void WSListener::set_ReadTimeout(std::chrono::seconds seconds)
    {
        for (auto &t : Impl_->ThreadContexts) {
            t->WebSocketContext_->ReadTimeout = seconds;
        }
    }
    std::chrono::seconds WSListener::get_ReadTimeout()
    {
        return Impl_->ThreadContexts.empty() ? std::chrono::seconds(1) : Impl_->ThreadContexts.front()->WebSocketContext_->ReadTimeout;
    }
    void WSListener::set_WriteTimeout(std::chrono::seconds seconds)
    {
        for (auto &t : Impl_->ThreadContexts) {
            t->WebSocketContext_->WriteTimeout = seconds;
        }
    }
    std::chrono::seconds WSListener::get_WriteTimeout()
    {
        return Impl_->ThreadContexts.empty() ? std::chrono::seconds(1) : Impl_->ThreadContexts.front()->WebSocketContext_->WriteTimeout;
    }
    void WSListener::set_MaxPayload(size_t bytes)
    {
        for (auto &t : Impl_->ThreadContexts) {
            t->WebSocketContext_->MaxPayload = bytes;
        }
    }
    size_t WSListener::get_MaxPayload()
    {
        return Impl_->ThreadContexts.empty() ? 1024 * 1024 * 20 : Impl_->ThreadContexts.front()->WebSocketContext_->MaxPayload;
    }

    std::shared_ptr<IWSListener_Configuration>
    WSListener_Configuration::onConnection(const std::function<void(const std::shared_ptr<IWebSocket> &, const HttpHeader &)> &handle)
    {
        for (auto &t : Impl_->ThreadContexts) {
            assert(!t->WebSocketContext_->onConnection);
            t->WebSocketContext_->onConnection = handle;
        }
        return std::make_shared<WSListener_Configuration>(Impl_);
    }
    std::shared_ptr<IWSListener_Configuration>
    WSListener_Configuration::onMessage(const std::function<void(const std::shared_ptr<IWebSocket> &, const WSMessage &)> &handle)
    {
        for (auto &t : Impl_->ThreadContexts) {
            assert(!t->WebSocketContext_->onMessage);
            t->WebSocketContext_->onMessage = handle;
        }
        return std::make_shared<WSListener_Configuration>(Impl_);
    }
    std::shared_ptr<IWSListener_Configuration> WSListener_Configuration::onDisconnection(
        const std::function<void(const std::shared_ptr<IWebSocket> &, unsigned short, const std::string &)> &handle)
    {

        for (auto &t : Impl_->ThreadContexts) {
            assert(!t->WebSocketContext_->onDisconnection);
            t->WebSocketContext_->onDisconnection = handle;
        }
        return std::make_shared<WSListener_Configuration>(Impl_);
    }
    std::shared_ptr<IWSListener_Configuration>
    WSListener_Configuration::onPing(const std::function<void(const std::shared_ptr<IWebSocket> &, const unsigned char *, size_t)> &handle)
    {
        for (auto &t : Impl_->ThreadContexts) {
            assert(!t->WebSocketContext_->onPing);
            t->WebSocketContext_->onPing = handle;
        }
        return std::make_shared<WSListener_Configuration>(Impl_);
    }
    std::shared_ptr<IWSListener_Configuration>
    WSListener_Configuration::onPong(const std::function<void(const std::shared_ptr<IWebSocket> &, const unsigned char *, size_t)> &handle)
    {

        for (auto &t : Impl_->ThreadContexts) {
            assert(!t->WebSocketContext_->onPong);
            t->WebSocketContext_->onPong = handle;
        }
        return std::make_shared<WSListener_Configuration>(Impl_);
    }
    std::shared_ptr<IWSHub> WSListener_Configuration::listen(bool no_delay, bool reuse_address)
    {
        if (Impl_->TLSEnabled) {
            auto createsocket = [](const std::shared_ptr<ThreadContext> &res) {

                return std::make_shared<WebSocket<true, asio::ssl::stream<asio::ip::tcp::socket>>>(res->WebSocketContext_, res->io_service,
                                                                                                   res->context);
            };
            Listen(Impl_, createsocket, no_delay, reuse_address);
        }
        else {
            auto createsocket = [](const std::shared_ptr<ThreadContext> &res) {
                return std::make_shared<WebSocket<true, asio::ip::tcp::socket>>(res->WebSocketContext_, res->io_service);
            };
            Listen(Impl_, createsocket, no_delay, reuse_address);
        }
        return std::make_shared<WSListener>(Impl_);
    }

} // namespace WS_LITE
} // namespace SL
