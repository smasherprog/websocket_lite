#pragma once
#include <memory>
#include <string>
#include <functional>
#include "Protocols.h"

namespace SL {
	namespace WS_LITE {
		struct HubConfig {
			std::string Password;
			unsigned short Port;
			std::string Privatekey_File;
			std::string Publiccertificate_File;
			std::string dh_File;
		};
		class WebSocket;

		class HubImpl;
		class Hub {
			std::shared_ptr<HubImpl> HubImpl_;
		public:
			Hub(const HubConfig& c);
			~Hub();

			void onConnection(std::function<void(std::weak_ptr<WebSocket>, HttpRequest)> handler);
			void onMessage(std::function<void(std::weak_ptr<WebSocket>, char *, size_t, OpCode)> handler);
			void onDisconnection(std::function<void(std::weak_ptr<WebSocket>, int code, char *message, size_t length)> handler);
			void onPing(std::function<void(std::weak_ptr<WebSocket>, char *, size_t)> handler);
			void onPong(std::function<void(std::weak_ptr<WebSocket>, char *, size_t)> handler);
	
			/*
			Future Work
			void onHttpRequest;
			void onHttpData;
			void onHttpConnection;
			void onHttpDisconnection;
			void onHttpUpgrade;
			void onCancelledHttpRequest;*/
			void Run();

		};
	}
}

