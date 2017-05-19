#include "WS_Lite.h"
#include "Logging.h"

#include <thread>
#include <chrono>
#include <string>

using namespace std::chrono_literals;

void wssautobahntest() {
    // auto listener = SL::WS_LITE::WSListener::CreateListener(3001, TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);
    auto listener = SL::WS_LITE::WSListener::CreateListener(3001);
    listener.onHttpUpgrade([](const SL::WS_LITE::WSocket& socket) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onHttpUpgrade");

    });
    listener.onConnection([](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");
    });
    listener.onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onMessage");
        SL::WS_LITE::WSMessage msg;
        msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char* p) { delete[] p; });
        msg.len = message.len;
        msg.code = message.code;
        msg.data = msg.Buffer.get();
        memcpy(msg.data, message.data, message.len);
        listener.send(socket, msg, false);
    });

    listener.startlistening();
    std::string cmd = "wstest -m fuzzingclient -s ";
    cmd += TEST_FUZZING_PATH;
    system(cmd.c_str());
}

int main(int argc, char* argv[]) {
    wssautobahntest();

    while (true) {
        std::this_thread::sleep_for(1s);
    }
    return 0;
}
//
//
//int main(int argc, char* argv[]) {
//
//    //auto listener = SL::WS_LITE::WSListener::CreateListener(3001, TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);
//    auto listener = SL::WS_LITE::WSListener::CreateListener(3001);
//    listener.onHttpUpgrade([](const SL::WS_LITE::WSocket& socket) {
//        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onHttpUpgrade");
//
//    });
//    listener.onConnection([](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
//        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");
//
//    });
//    listener.onDisconnection([](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
//        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onDisconnection");
//    });
//    listener.startlistening();
//
//    //auto client = SL::WS_LITE::WSClient::CreateClient(TEST_CERTIFICATE_PUBLIC_PATH);
//    auto client = SL::WS_LITE::WSClient::CreateClient();
//    bool waitingconnection = true;
//    client.onHttpUpgrade([](const SL::WS_LITE::WSocket& socket) {
//        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onHttpUpgrade");
//
//    });
//    client.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
//        waitingconnection = false;
//        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onConnection");
//    });    
//    client.onDisconnection([](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
//        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "client::onDisconnection");
//    });
//    client.connect("localhost", 3001);
//
//    while (true) {
//        std::this_thread::sleep_for(1s);
//    }
//    return 0;
//}
