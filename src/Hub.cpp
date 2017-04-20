#include "Hub.h"
#include "internal/HubImpl.h"

namespace SL {
	namespace WS_LITE {

		Hub::Hub(const HubConfig & c)
		{
			HubImpl_ = std::make_shared<HubImpl>(c);
		}

		Hub::~Hub()
		{
		}

		void Hub::onConnection(std::function<void(std::weak_ptr<WebSocket>)> handler)
		{
			HubImpl_->OnConnectionHandler = handler;
		}


		void Hub::onMessage(std::function<void(std::weak_ptr<WebSocket>, char*, size_t, OpCode)> handler)
		{
			HubImpl_->OnMessageHandler = handler;
		}

		void Hub::onDisconnection(std::function<void(std::weak_ptr<WebSocket>, int code, char*message, size_t length)> handler)
		{
			HubImpl_->OnDisconnectHandler = handler;
		}

		void Hub::onPing(std::function<void(std::weak_ptr<WebSocket>, char*, size_t)> handler)
		{
			HubImpl_->OnPingHandler = handler;
		}

		void Hub::onPong(std::function<void(std::weak_ptr<WebSocket>, char*, size_t)> handler)
		{
			HubImpl_->OnPongHandler = handler;
		}

		void Hub::onHttpUpgrade(std::function<void(std::weak_ptr<WebSocket>)> handler)
		{
			HubImpl_->OnHttpUpgrade = handler;
		}

		void Hub::Run()
		{
			HubImpl_->Listen();
		}

	}
}
