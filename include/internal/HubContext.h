#pragma once
#include "ThreadContext.h"
#include "WS_Lite.h"
#include <atomic>
#include <chrono>
#include <functional>

namespace SL {
namespace WS_LITE {
    class IWebSocket;
    class HubContext {
      public:
        HubContext(ThreadCount threadcount, asio::ssl::context_base::method m);
        HubContext(ThreadCount threadcount);
        ~HubContext();
        auto getnextContext() { return ThreadContexts[(m_nextService++ % ThreadContexts.size())]; }
        std::atomic<std::size_t> m_nextService{0};
        std::vector<std::shared_ptr<ThreadContext>> ThreadContexts;
        std::unique_ptr<asio::ip::tcp::acceptor> acceptor;
        bool TLSEnabled = false;
    };

} // namespace WS_LITE
} // namespace SL