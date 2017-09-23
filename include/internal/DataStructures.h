#pragma once
#include "Logging.h"
#include "Utils.h"
#include "WS_Lite.h"

#include <deque>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#if WIN32
#include <SDKDDKVer.h>
#include <Windows.h>
#include <wincrypt.h>
#endif
#include "asio.hpp"
#include "asio/deadline_timer.hpp"
#include "asio/ssl.hpp"

namespace SL {
namespace WS_LITE {
    class WSContextImpl;
    template <bool isServer, class SOCKETTYPE, class SENDBUFFERTYPE>
    void sendImpl(const std::shared_ptr<WSContextImpl> parent, const SOCKETTYPE &socket, const SENDBUFFERTYPE &msg, bool compressmessage);
    template <bool isServer, class SOCKETTYPE>
    void sendclosemessage(const std::shared_ptr<WSContextImpl> parent, const SOCKETTYPE &socket, unsigned short code, const std::string &msg);

    struct WSSendMessageInternal {
        unsigned char *data;
        size_t len;
        OpCode code;
        // compress the outgoing message?
        bool Compress;
    };

    struct ThreadContext {
        std::unique_ptr<char[]> inflationBuffer;
        z_stream inflationStream = {};
        std::thread Thread;
    };
    const auto CONTROLBUFFERMAXSIZE = 125;
    enum method;
    class WSContextImpl {
      public:
        WSContextImpl(ThreadCount threadcount, method m)
            : work(std::make_unique<asio::io_service::work>(io_service)), sslcontext(static_cast<asio::ssl::context_base::method>(m)),
              TLSEnabled(true)
        {
            Threads.resize(threadcount.value);
            for (auto &ctx : Threads) {
                inflateInit2(&ctx.inflationStream, -MAX_WBITS);
                ctx.inflationBuffer = std::make_unique<char[]>(LARGE_BUFFER_SIZE);
                ctx.Thread = std::thread([&]() {
                    std::error_code ec;
                    io_service.run(ec);
                });
            }
        }
        WSContextImpl(ThreadCount threadcount)
            : work(std::make_unique<asio::io_service::work>(io_service)), sslcontext(asio::ssl::context::tlsv11), TLSEnabled(false)
        {
            Threads.resize(threadcount.value);
            for (auto &ctx : Threads) {
                inflateInit2(&ctx.inflationStream, -MAX_WBITS);
                ctx.inflationBuffer = std::make_unique<char[]>(LARGE_BUFFER_SIZE);
                ctx.Thread = std::thread([&]() {
                    std::error_code ec;
                    io_service.run(ec);
                });
            }
        }
        ~WSContextImpl()
        {
            if (acceptor) {
                std::error_code ec;
                acceptor->close(ec);
            }
            work.reset();
            io_service.stop();
            while (!io_service.stopped()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            for (auto &t : Threads) {
                inflateEnd(&t.inflationStream);
                if (t.Thread.joinable()) {
                    if (std::this_thread::get_id() == t.Thread.get_id()) {
                        t.Thread.detach(); // I am destroying myself.. detach
                    }
                    else {
                        t.Thread.join();
                    }
                }
            }
            Threads.clear();
        }

        asio::io_service io_service;
        std::vector<ThreadContext> Threads;
        std::unique_ptr<asio::io_service::work> work;
        std::unique_ptr<asio::ip::tcp::acceptor> acceptor;

        asio::ssl::context sslcontext;
        std::chrono::seconds ReadTimeout = std::chrono::seconds(30);
        std::chrono::seconds WriteTimeout = std::chrono::seconds(30);
        size_t MaxPayload = 1024 * 1024 * 20; // 20 MB
        bool TLSEnabled = false;

        std::function<void(const std::shared_ptr<IWSocket> &, const std::unordered_map<std::string, std::string> &)> onConnection;
        std::function<void(const std::shared_ptr<IWSocket> &, const WSMessage &)> onMessage;
        std::function<void(const std::shared_ptr<IWSocket> &, unsigned short, const std::string &)> onDisconnection;
        std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> onPing;
        std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> onPong;
    };

    struct SendQueueItem {
        WSMessage msg;
        bool compressmessage;
    };

    template <bool isServer, class SOCKETTYPE> class WSocket : public IWSocket {

      public:
        WSocket(const std::shared_ptr<WSContextImpl> &s, asio::ssl::context &sslcontext)
            : Parent(s), Socket(s->io_service, sslcontext), ping_deadline(s->io_service), read_deadline(s->io_service), write_deadline(s->io_service),
              strand(s->io_service)
        {
        }
        WSocket(const std::shared_ptr<WSContextImpl> &s)
            : Parent(s), Socket(s->io_service), ping_deadline(s->io_service), read_deadline(s->io_service), write_deadline(s->io_service),
              strand(s->io_service)
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
        virtual SocketStatus is_open() const { return SocketStatus_; }
        virtual std::string get_address() const { return SL::WS_LITE::get_address(Socket); }
        virtual unsigned short get_port() const { return SL::WS_LITE::get_port(Socket); }
        virtual bool is_v4() const { return SL::WS_LITE::is_v4(Socket); }
        virtual bool is_v6() const { return SL::WS_LITE::is_v6(Socket); }
        virtual bool is_loopback() const { return SL::WS_LITE::is_loopback(Socket); }
        virtual void send(const WSMessage &msg, bool compressmessage)
        {
            if (SocketStatus_ == SocketStatus::CONNECTED) { // only send a close to an open socket
                auto self(std::static_pointer_cast<WSocket<isServer, SOCKETTYPE>>(shared_from_this()));
                auto p(Parent);
                if (p)
                    sendImpl<isServer>(p, self, msg, compressmessage);
            }
        }
        // send a close message and close the socket
        virtual void close(unsigned short code, const std::string &msg)
        {
            if (SocketStatus_ == SocketStatus::CONNECTED) { // only send a close to an open socket
                auto self(std::static_pointer_cast<WSocket<isServer, SOCKETTYPE>>(shared_from_this()));
                auto p(Parent);
                if (p)
                    sendclosemessage<isServer>(p, self, code, msg);
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
        std::shared_ptr<WSContextImpl> Parent;
        SOCKETTYPE Socket;

        asio::basic_waitable_timer<std::chrono::steady_clock> ping_deadline;
        asio::basic_waitable_timer<std::chrono::steady_clock> read_deadline;
        asio::basic_waitable_timer<std::chrono::steady_clock> write_deadline;
        asio::strand strand;
        std::deque<SendQueueItem> SendMessageQueue;
    };

} // namespace WS_LITE
} // namespace SL