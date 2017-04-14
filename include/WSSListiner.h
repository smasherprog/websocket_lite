#pragma once
#include <memory>
#include <string>

namespace SL {
	namespace WS_LITE {
		struct WSSListenerConfig {
			std::string Password;
			unsigned short Port;
			std::string Privatekey_File;
			std::string Publiccertificate_File;
			std::string dh_File;
		};
		class WSSListinerImpl;
		class WSSListiner {
			std::unique_ptr<WSSListinerImpl> WSSListinerImpl_;
		public:
			WSSListiner(const WSSListenerConfig& c);
			~WSSListiner();
			void Listen();

		};
	}
}

