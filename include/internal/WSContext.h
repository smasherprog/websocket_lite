#pragma once
#include "ThreadContext.h"
#include "WS_Lite.h"
#include <atomic>
#include <chrono>
#include <functional>

namespace SL {
namespace WS_LITE {
    class IWSocket;
    class WSContext {
      public:
        WSContext(ThreadCount threadcount, asio::ssl::context_base::method m);
        WSContext(ThreadCount threadcount);
        ~WSContext();
        ThreadContext &getnextContext() { return *ThreadContexts[(m_nextService++ % ThreadContexts.size())]; }
        std::atomic<std::size_t> m_nextService{0};
        std::vector<std::shared_ptr<ThreadContext>> ThreadContexts;
        std::unique_ptr<asio::ip::tcp::acceptor> acceptor;

        std::chrono::seconds ReadTimeout = std::chrono::seconds(30);
        std::chrono::seconds WriteTimeout = std::chrono::seconds(30);
        size_t MaxPayload = 1024 * 1024 * 20; // 20 MB
        bool TLSEnabled = false;
        ExtensionOptions ExtensionOptions_ = ExtensionOptions::NO_OPTIONS;

        std::function<void(const std::shared_ptr<IWSocket> &, const HttpHeader &)> onConnection;
        std::function<void(const std::shared_ptr<IWSocket> &, const WSMessage &)> onMessage;
        std::function<void(const std::shared_ptr<IWSocket> &, unsigned short, const std::string &)> onDisconnection;
        std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> onPing;
        std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> onPong;
    };

} // namespace WS_LITE
} // namespace SL