#include "WS_Lite.h"
#include <thread>
#include <chrono>

using namespace std::chrono_literals;

int main(int argc, char* argv[]) {

	auto listener = SL::WS_LITE::CreateListener(12345, TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);
	SL::WS_LITE::onHttpUpgrade(listener, [](std::weak_ptr<SL::WS_LITE::WSocket> socket) {


	});
	SL::WS_LITE::onConnection(listener, [](std::weak_ptr<SL::WS_LITE::WSocket> socket, const std::unordered_map<std::string, std::string>& header) {


	});
	SL::WS_LITE::StartListening(listener);


	auto client = SL::WS_LITE::CreateClient(TEST_CERTIFICATE_PUBLIC_PATH);
	bool waitingconnection = true;
	SL::WS_LITE::onHttpUpgrade(client, [](std::weak_ptr<SL::WS_LITE::WSocket> socket) {


	});
	SL::WS_LITE::onConnection(client, [&](std::weak_ptr<SL::WS_LITE::WSocket> socket, const std::unordered_map<std::string, std::string>& header) {
		waitingconnection = false;

	});	
	SL::WS_LITE::Connect(client, "localhost", 12345);
	
	while (true) {
		std::this_thread::sleep_for(1s);
	}
	return 0;
}