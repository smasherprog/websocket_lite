#pragma once
#include "Logging.h"
#include "WS_Lite.h"

#if WIN32
#include <SDKDDKVer.h>
#endif
#include "asio.hpp"
#include "asio/ssl.hpp"
#include <deque>
#include <memory>
#include <string>

namespace SL {
namespace WS_LITE {

    struct SendQueueItem {
        WSMessage msg;
        CompressionOptions compressmessage;
    };
    class WSContext;
    template <bool isServer, class SOCKETTYPE> class WSocket final : public IWSocket {

      public:
        WSocket(const std::shared_ptr<WSContext> &s, asio::io_service &ioservice, asio::ssl::context &sslcontext)
            : Parent(s), Socket(ioservice, sslcontext), ping_deadline(ioservice), read_deadline(ioservice), write_deadline(ioservice)
        {
        }
        WSocket(const std::shared_ptr<WSContext> &s, asio::io_service &ioservice)
            : Parent(s), Socket(ioservice), ping_deadline(ioservice), read_deadline(ioservice), write_deadline(ioservice)
        {
        }
        virtual ~WSocket()
        {
            SocketStatus_ = SocketStatus::CLOSED;
            canceltimers();
            if (ReceiveBuffer) {
                free(ReceiveBuffer);
            }
        }
        virtual SocketStatus is_open() const override { return SocketStatus_; }
        virtual std::string get_address() const override
        {

            std::error_code ec;
            auto rt(Socket.lowest_layer().remote_endpoint(ec));
            if (!ec)
                return rt.address().to_string();
            else
                return "";
        }
        virtual unsigned short get_port() const override
        {
            std::error_code ec;
            auto rt(Socket.lowest_layer().remote_endpoint(ec));
            if (!ec)
                return rt.port();
            else
                return static_cast<unsigned short>(-1);
        }
        virtual bool is_v4() const override
        {
            std::error_code ec;
            auto rt(Socket.lowest_layer().remote_endpoint(ec));
            if (!ec)
                return rt.address().is_v4();
            else
                return true;
        }
        virtual bool is_v6() const override
        {
            std::error_code ec;
            auto rt(Socket.lowest_layer().remote_endpoint(ec));
            if (!ec)
                return rt.address().is_v6();
            else
                return true;
        }
        virtual size_t BufferedBytes() const override { return Bytes_PendingFlush; }
        virtual bool is_loopback() const override
        {
            std::error_code ec;
            auto rt(Socket.lowest_layer().remote_endpoint(ec));
            if (!ec)
                return rt.address().is_loopback();
            else
                return true;
        }
        virtual void send(const WSMessage &msg, CompressionOptions compressmessage) override
        {
            if (SocketStatus_ == SocketStatus::CONNECTED) { // only send to a conected socket
                auto self(std::static_pointer_cast<WSocket<isServer, SOCKETTYPE>>(shared_from_this()));
                auto p(Parent);
                if (p) {
                    sendImpl<isServer>(p, self, msg, compressmessage);
                }
            }
        }
        // send a close message and close the socket
        virtual void close(unsigned short code, const std::string &msg) override
        {
            if (SocketStatus_ == SocketStatus::CONNECTED) { // only send a close to an open socket
                auto self(std::static_pointer_cast<WSocket<isServer, SOCKETTYPE>>(shared_from_this()));
                auto p(Parent);
                if (p) {
                    sendclosemessage<isServer>(p, self, code, msg);
                }
            }
        }
        void canceltimers()
        {
            std::error_code ec;
            read_deadline.cancel(ec);
            ec.clear();
            write_deadline.cancel(ec);
            ec.clear();
            ping_deadline.cancel(ec);
        }

        unsigned char *ReceiveBuffer = nullptr;
        size_t ReceiveBufferSize = 0;
        unsigned char ReceiveHeader[14] = {};
        bool CompressionEnabled = false;
        SocketStatus SocketStatus_ = SocketStatus::CLOSED;
        bool Writing = false;
        OpCode LastOpCode = OpCode::INVALID;
        std::shared_ptr<WSContext> Parent;
        SOCKETTYPE Socket;
        size_t Bytes_PendingFlush = 0;

        asio::basic_waitable_timer<std::chrono::steady_clock> ping_deadline;
        asio::basic_waitable_timer<std::chrono::steady_clock> read_deadline;
        asio::basic_waitable_timer<std::chrono::steady_clock> write_deadline;
        std::deque<SendQueueItem> SendMessageQueue;
    };

} // namespace WS_LITE
} // namespace SL