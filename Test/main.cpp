#include "WS_Lite.h"
#include "Logging.h"

#include <thread>
#include <chrono>
#include <string>
#include <cstring>
#include <iostream>
#include <vector>
#include <atomic>

using namespace std::chrono_literals;

void wssautobahntest() {
    // auto listener = SL::WS_LITE::WSListener::CreateListener(3001, TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);

    SL::WS_LITE::PortNumber port(3001);
    SL::WS_LITE::WSContext ctx(SL::WS_LITE::ThreadCount(4));

    auto listener = ctx.CreateListener(SL::WS_LITE::PortNumber(3000));
    listener.set_ReadTimeout(std::chrono::seconds(100));
    listener.set_WriteTimeout(std::chrono::seconds(100));
    auto lastheard = std::chrono::high_resolution_clock::now();
    listener.onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onHttpUpgrade");
    });
    listener.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");
    });
    listener.onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL::WS_LITE::WSMessage msg;
        msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char* p) { delete[] p; });
        msg.len = message.len;
        msg.code = message.code;
        msg.data = msg.Buffer.get();
        memcpy(msg.data, message.data, message.len);
        listener.send(socket, msg, false);
    });

    listener.startlistening();

    auto tlslistener = ctx.CreateListener(SL::WS_LITE::PortNumber(3001), TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);
    tlslistener.set_ReadTimeout(std::chrono::seconds(100));
    tlslistener.set_WriteTimeout(std::chrono::seconds(100));
    tlslistener.onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "tlslistener::onHttpUpgrade");
    });
    tlslistener.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "tlslistener::onConnection");
    });
    tlslistener.onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL::WS_LITE::WSMessage msg;
        msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char* p) { delete[] p; });
        msg.len = message.len;
        msg.code = message.code;
        msg.data = msg.Buffer.get();
        memcpy(msg.data, message.data, message.len);
        tlslistener.send(socket, msg, false);
    });
    tlslistener.startlistening();

    std::string cmd = "wstest -m fuzzingclient -s ";
    cmd += TEST_FUZZING_PATH;
    system(cmd.c_str());
    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 2000) {
        std::this_thread::sleep_for(200ms);
    }
    std::cout << "Exiting autobahn test..." << std::endl;
}
void generaltest() {
    std::cout << "Starting General test..." << std::endl;
    //auto listener = SL::WS_LITE::WSListener::CreateListener(3002, TEST_CERTIFICATE_PRIVATE_PASSWORD, TEST_CERTIFICATE_PRIVATE_PATH, TEST_CERTIFICATE_PUBLIC_PATH, TEST_DH_PATH);

    SL::WS_LITE::PortNumber port(3002);
    SL::WS_LITE::WSContext ctx(SL::WS_LITE::ThreadCount(1));
    auto listener = ctx.CreateListener(port);
    auto lastheard = std::chrono::high_resolution_clock::now();
    listener.onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onHttpUpgrade");

    });
    listener.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");

    });
    listener.onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL::WS_LITE::WSMessage msg;
        msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char* p) { delete[] p; });
        msg.len = message.len;
        msg.code = message.code;
        msg.data = msg.Buffer.get();
        memcpy(msg.data, message.data, message.len);
        listener.send(socket, msg, false);
    });
    listener.onDisconnection([&](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onDisconnection");
    });
    listener.startlistening();

    //auto client = SL::WS_LITE::WSClient::CreateClient(TEST_CERTIFICATE_PUBLIC_PATH);

    auto client = ctx.CreateClient();
    client.onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onHttpUpgrade");

    });
    client.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onConnection");
    });
    client.onDisconnection([&](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "client::onDisconnection");
    });
    client.connect("localhost", port);

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 2000) {
        std::this_thread::sleep_for(200ms);
    }
}
void multithreadtest() {
    std::cout << "Starting Multi threaded test..." << std::endl;

    SL::WS_LITE::PortNumber port(3003);
    SL::WS_LITE::WSContext ctx(SL::WS_LITE::ThreadCount(4));

    auto listener = ctx.CreateListener(port);
    auto lastheard = std::chrono::high_resolution_clock::now();
    listener.onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
        lastheard = std::chrono::high_resolution_clock::now();
    });
    listener.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        lastheard = std::chrono::high_resolution_clock::now();
    });
    listener.onDisconnection([&](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
        lastheard = std::chrono::high_resolution_clock::now();
    });    
    listener.onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
        lastheard = std::chrono::high_resolution_clock::now();
        SL::WS_LITE::WSMessage msg;
        msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char* p) { delete[] p; });
        msg.len = message.len;
        msg.code = message.code;
        msg.data = msg.Buffer.get();
        memcpy(msg.data, message.data, message.len);
        listener.send(socket, msg, false);
    });
    listener.startlistening();
    std::vector<SL::WS_LITE::WSClient> clients;
    clients.reserve(100);
    for (auto i = 0; i < 100; i++) {

        clients.push_back(ctx.CreateClient());
        clients[i].onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
            lastheard = std::chrono::high_resolution_clock::now();
        });
        clients[i].onConnection([&clients, &lastheard, i](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
            lastheard = std::chrono::high_resolution_clock::now();
            SL::WS_LITE::WSMessage msg;
            std::string txtmsg = "testing msg";
            txtmsg += std::to_string(i);
            msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[txtmsg.size()], [](unsigned char* p) { delete[] p; });
            msg.len = txtmsg.size();
            msg.code = SL::WS_LITE::OpCode::TEXT;
            msg.data = msg.Buffer.get();
            memcpy(msg.data, txtmsg.data(), txtmsg.size());
            clients[i].send(socket, msg, false);
        });
        clients[i].onDisconnection([&](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
            lastheard = std::chrono::high_resolution_clock::now();
        });
        clients[i].onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
            lastheard = std::chrono::high_resolution_clock::now();
        });
        clients[i].connect("localhost", port);
     
    }

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 2000) {
        std::this_thread::sleep_for(200ms);
    }
}
void multithreadthroughputtest() {
    std::cout << "Starting Multi threaded throughput test" << std::endl;

    SL::WS_LITE::PortNumber port(3004);
    SL::WS_LITE::WSContext listenerctx(SL::WS_LITE::ThreadCount(8));
    std::vector<SL::WS_LITE::WSClient> clients;
    clients.reserve(50);//this should use about 1 GB of memory between sending and receiving

    auto recvtimer = std::chrono::high_resolution_clock::now();

    auto listener = listenerctx.CreateListener(port);
    auto lastheard = std::chrono::high_resolution_clock::now();
    std::atomic<unsigned long long> mbsreceived;
    mbsreceived = 0;
    const auto bufferesize = 1024 * 1024 * 10;
    listener.onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
        lastheard = std::chrono::high_resolution_clock::now();
    });
    listener.onConnection([&](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
        lastheard = std::chrono::high_resolution_clock::now();
    });
    listener.onDisconnection([&](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
        lastheard = std::chrono::high_resolution_clock::now();
    });
    listener.onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
        lastheard = std::chrono::high_resolution_clock::now();
        mbsreceived += message.len;
        if (mbsreceived == bufferesize* clients.capacity()) {
            std::cout << "Took " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - recvtimer).count() << "ms to receive " << bufferesize * clients.capacity() << " bytes" << std::endl;
        }
    });
    listener.startlistening();

    std::atomic<unsigned long long> mbssent;
    mbssent = 0;
    SL::WS_LITE::WSContext clientctx(SL::WS_LITE::ThreadCount(8));
    auto sendtimer = std::chrono::high_resolution_clock::now();
    for (auto i = 0; i < clients.capacity(); i++) {

        clients.push_back(clientctx.CreateClient());
        clients[i].onHttpUpgrade([&](const SL::WS_LITE::WSocket& socket) {
            lastheard = std::chrono::high_resolution_clock::now();
        });
        clients[i].onConnection([&clients, &lastheard, i, &mbssent, &sendtimer, bufferesize](const SL::WS_LITE::WSocket& socket, const std::unordered_map<std::string, std::string>& header) {
            lastheard = std::chrono::high_resolution_clock::now();
            SL::WS_LITE::WSMessage msg;
            msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[bufferesize], [&](unsigned char* p) {
                mbssent += bufferesize;
                if (mbssent == bufferesize * clients.capacity()) {
                    std::cout << "Took " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()- sendtimer).count() << "ms to send " << bufferesize * clients.capacity() <<" bytes" << std::endl;
                }
                delete[] p; 
            });
            msg.len = bufferesize;//10MB
            msg.code = SL::WS_LITE::OpCode::BINARY;
            msg.data = msg.Buffer.get();
            clients[i].send(socket, msg, false);
        });
        clients[i].onDisconnection([&](const SL::WS_LITE::WSocket& socket, unsigned short code, const std::string& msg) {
            lastheard = std::chrono::high_resolution_clock::now();
        });
        clients[i].onMessage([&](const SL::WS_LITE::WSocket& socket, const SL::WS_LITE::WSMessage& message) {
            lastheard = std::chrono::high_resolution_clock::now();
        });
        clients[i].connect("localhost", port);
    }

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 50000) {
        std::this_thread::sleep_for(200ms);
    }
    std::cout << "Received " << mbsreceived<<"  bytes"<< std::endl;
}
int main(int argc, char* argv[]) {
    wssautobahntest();
    std::this_thread::sleep_for(1s);
    generaltest();
    std::this_thread::sleep_for(1s);
    multithreadtest();
    std::this_thread::sleep_for(1s);
    multithreadthroughputtest();
    return 0;
}
