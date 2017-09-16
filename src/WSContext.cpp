#include "WS_Lite.h"
#include "internal/WebSocketProtocol.h"
#include <memory>

namespace SL {
namespace WS_LITE {

    class WSContext : public IWSContext {
        std::shared_ptr<WSContextImpl> WSContextImpl_;

      public:
        WSContext(const std::shared_ptr<WSContextImpl> &c) : WSContextImpl_(c) {}
        virtual ~WSContext() {}

        virtual std::shared_ptr<IWSListener_Configuration> CreateListener(PortNumber port, ExtensionOptions options) override
        {
            return std::make_shared<WSListener_Configuration>(std::make_shared<WSListenerImpl>(WSContextImpl_, port));
        }
        virtual std::shared_ptr<IWSListener_Configuration> CreateTLSListener(PortNumber port, std::string Password, std::string Privatekey_File,
                                                                             std::string Publiccertificate_File, std::string dh_File,
                                                                             ExtensionOptions options) override
        {
            return std::make_shared<WSListener_Configuration>(
                std::make_shared<WSListenerImpl>(WSContextImpl_, port, Password, Privatekey_File, Publiccertificate_File, dh_File));
        };
        virtual std::shared_ptr<IWSClient_Configuration> CreateClient(ExtensionOptions options) override
        {
            return std::make_shared<WSClient_Configuration>(std::make_shared<WSClientImpl>(WSContextImpl_));
        }
        virtual std::shared_ptr<IWSSClient_Configuration> CreateTLSClient(ExtensionOptions options) override
        {
            return std::make_shared<WSSClient_Configuration>(std::make_shared<WSClientImpl>(WSContextImpl_, true));
        }
        virtual std::shared_ptr<IWSSClient_Configuration> CreateTLSClient(std::string Publiccertificate_File, ExtensionOptions options) override
        {
            return std::make_shared<WSSClient_Configuration>(std::make_shared<WSClientImpl>(WSContextImpl_, Publiccertificate_File));
        }
    };

    std::shared_ptr<IWSContext> CreateContext(ThreadCount threadcount)
    {
        return std::make_shared<WSContext>(std::make_shared<WSContextImpl>(threadcount));
    }
} // namespace WS_LITE
} // namespace SL
