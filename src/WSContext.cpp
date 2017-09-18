#include "WS_Lite.h"
#include "internal/WebSocketProtocol.h"
#include <memory>

namespace SL {
namespace WS_LITE {

    class WSContext_Configuration : public IWSContext_Configuration {
        std::shared_ptr<WSContextImpl> WSContextImpl_;

      public:
        WSContext_Configuration(const std::shared_ptr<WSContextImpl> &c) : WSContextImpl_(c) {}
        virtual ~WSContext_Configuration() {}

        virtual std::shared_ptr<IWSListener_Configuration> CreateListener(PortNumber port, ExtensionOptions options) override
        {
            WSContextImpl_->acceptor =
                std::make_unique<asio::ip::tcp::acceptor>(WSContextImpl_->io_service, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port.value));
            return std::make_shared<WSListener_Configuration>(std::make_shared<WSListenerImpl>(WSContextImpl_, port));
        }
        virtual std::shared_ptr<IWSClient_Configuration> CreateClient(ExtensionOptions options) override
        {
            return std::make_shared<WSClient_Configuration>(std::make_shared<WSClientImpl>(WSContextImpl_));
        }
    };
    class TLS_Configuration : public ITLS_Configuration {
        std::shared_ptr<DelayedInfo> impl;

      public:
        TLS_Configuration(const std::shared_ptr<DelayedInfo> &c) : impl(c) {}
        virtual ~TLS_Configuration() {}

        virtual std::shared_ptr<IWSContext_Configuration> UseTLS(const std::function<void(TLSContext &context)> &callback, method m) override
        {
            auto ret = std::make_shared<WSContextImpl>(impl->threadcount, m);
            ret->TLSEnabled = true;
            TLSContext tlscontext;
            tlscontext.impl = ret;
            callback(tlscontext);
            return std::make_shared<WSContext_Configuration>(ret);
        }
        virtual std::shared_ptr<IWSContext_Configuration> NoTLS() override
        {
            auto ret = std::make_shared<WSContextImpl>(impl->threadcount);
            ret->TLSEnabled = false;
            return std::make_shared<WSContext_Configuration>(ret);
        }
    };
    std::shared_ptr<ITLS_Configuration> CreateContext(ThreadCount threadcount)
    {
        auto ret = std::make_shared<DelayedInfo>();
        ret->threadcount = threadcount;
        return std::make_shared<TLS_Configuration>(ret);
    }
} // namespace WS_LITE
} // namespace SL
