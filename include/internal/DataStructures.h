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
    void sendImpl(const std::shared_ptr<WSContextImpl> parent, const SOCKETTYPE &socket, const SENDBUFFERTYPE &msg,
                  CompressionOptions compressmessage);
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
        ThreadContext(asio::ssl::context_base::method m) : work(io_service), context(m), inflationBuffer(std::make_unique<char[]>(LARGE_BUFFER_SIZE))
        {
            inflateInit2(&inflationStream, -MAX_WBITS);
            thread = std::thread([&] {
                std::error_code ec;
                io_service.run(ec);
            });
        }
        std::unique_ptr<char[]> inflationBuffer;
        z_stream inflationStream = {};
        std::thread thread;
        asio::io_service io_service;
        asio::io_service::work work;
        asio::ssl::context context;
    };

    const auto CONTROLBUFFERMAXSIZE = 125;

    class WSContextImpl {
      public:
        WSContextImpl(ThreadCount threadcount, method *m = nullptr)
        {
            TLSEnabled = m ? true : false;
            auto met = asio::ssl::context_base::method::tlsv12;
            if (m) {
                met = static_cast<asio::ssl::context_base::method>(*m);
            }
            for (auto i = 0; i < threadcount.value; i++) {
                ThreadContexts.push_back(std::make_shared<ThreadContext>(met));
            }
        }
        ~WSContextImpl()
        {
            if (acceptor) {
                std::error_code ec;
                acceptor->close(ec);
            }
            for (auto &t : ThreadContexts) {
                t->io_service.stop();
                inflateEnd(&t->inflationStream);
                if (t->thread.joinable()) {
                    if (std::this_thread::get_id() == t->thread.get_id()) {
                        t->thread.detach(); // I am destroying myself.. detach
                    }
                    else {
                        t->thread.join();
                    }
                }
            }
            ThreadContexts.clear();
        }
        ThreadContext &get() { return *ThreadContexts[(m_nextService++ % ThreadContexts.size())]; }
        std::atomic<std::size_t> m_nextService{0};
        std::vector<std::shared_ptr<ThreadContext>> ThreadContexts;
        std::unique_ptr<asio::ip::tcp::acceptor> acceptor;

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
        CompressionOptions compressmessage;
    };

    template <bool isServer, class SOCKETTYPE> class WSocket : public IWSocket {

      public:
        WSocket(const std::shared_ptr<WSContextImpl> &s, asio::io_service &ioservice, asio::ssl::context &sslcontext)
            : Parent(s), Socket(ioservice, sslcontext), ping_deadline(ioservice), read_deadline(ioservice), write_deadline(ioservice)
        {
        }
        WSocket(const std::shared_ptr<WSContextImpl> &s, asio::io_service &ioservice)
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
        virtual std::string get_address() const override { return SL::WS_LITE::get_address(Socket); }
        virtual unsigned short get_port() const override { return SL::WS_LITE::get_port(Socket); }
        virtual bool is_v4() const override { return SL::WS_LITE::is_v4(Socket); }
        virtual bool is_v6() const override { return SL::WS_LITE::is_v6(Socket); }
        virtual size_t BufferedBytes() const override { return Bytes_PendingFlush; }
        virtual bool is_loopback() const override { return SL::WS_LITE::is_loopback(Socket); }
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
        std::shared_ptr<WSContextImpl> Parent;
        SOCKETTYPE Socket;
        size_t Bytes_PendingFlush = 0;

        asio::basic_waitable_timer<std::chrono::steady_clock> ping_deadline;
        asio::basic_waitable_timer<std::chrono::steady_clock> read_deadline;
        asio::basic_waitable_timer<std::chrono::steady_clock> write_deadline;
        std::deque<SendQueueItem> SendMessageQueue;
    };

} // namespace WS_LITE
} // namespace SL