#include "WS_Lite.h"

int main(int argc, char* argv[]) {

	auto listener = SL::WS_LITE::CreateListener(12345, TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);
	SL::WS_LITE::onHttpUpgrade(listener, [](std::weak_ptr<SL::WS_LITE::WSocket> socket) {


	});
	SL::WS_LITE::onConnection(listener, [](std::weak_ptr<SL::WS_LITE::WSocket> socket, const std::unordered_map<std::string, std::string>& header) {


	});
	SL::WS_LITE::StartListening(listener);


	auto client = SL::WS_LITE::CreateClient(TEST_CERTIFICATE_PUBLIC_PATH);

	SL::WS_LITE::onHttpUpgrade(client, [](std::weak_ptr<SL::WS_LITE::WSocket> socket) {


	});
	SL::WS_LITE::onConnection(client, [](std::weak_ptr<SL::WS_LITE::WSocket> socket, const std::unordered_map<std::string, std::string>& header) {


	});	
	SL::WS_LITE::Connect(client, "localhost", 12345);
	

	return 0;
}