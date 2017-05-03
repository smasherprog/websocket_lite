#include "WS_Lite.h"
#include "Logging.h"

#include <thread>
#include <chrono>

using namespace std::chrono_literals;

void wssautobahntest() {
    auto listener = SL::WS_LITE::WSListener::CreateListener(3001, TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);
    listener.onHttpUpgrade([](SL::WS_LITE::WSocket socket) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onHttpUpgrade");

    });
    listener.onConnection([](SL::WS_LITE::WSocket socket, const std::unordered_map<std::string, std::string>& header) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");
    });
    listener.startlistening();
    system("wstest -m fuzzingclient -s wssfuzzingclient.json");
}
int main(int argc, char* argv[]) {

    wssautobahntest();
    while (true) {
        std::this_thread::sleep_for(1s);
    }
    return 0;
}

/*
int main(int argc, char* argv[]) {

    auto listener = SL::WS_LITE::WSListener::CreateListener(12345, TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);
    listener.onHttpUpgrade([](SL::WS_LITE::WSocket socket) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onHttpUpgrade");

    });
    listener.onConnection([](SL::WS_LITE::WSocket socket, const std::unordered_map<std::string, std::string>& header) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");

    });
    listener.startlistening();

    auto client = SL::WS_LITE::WSClient::CreateClient(TEST_CERTIFICATE_PUBLIC_PATH);
    bool waitingconnection = true;
    client.onHttpUpgrade([](SL::WS_LITE::WSocket socket) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onHttpUpgrade");

    });
    client.onConnection([&](SL::WS_LITE::WSocket socket, const std::unordered_map<std::string, std::string>& header) {
        waitingconnection = false;
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onConnection");
    });
    client.connect("localhost", 12345);

    while (true) {
        std::this_thread::sleep_for(1s);
    }
    return 0;
}*/