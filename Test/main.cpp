#include "Logging.h"
#include "WS_Lite.h"
#include "internal\HeaderParser.h"
#include "internal\Utils.h"

#include <assert.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
inline std::ifstream::pos_type filesize(const std::string &filename)
{
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

void wssautobahntest()
{

    auto lastheard = std::chrono::high_resolution_clock::now();

    auto listener =
        SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(1))
            ->NoTLS()
            ->CreateListener(SL::WS_LITE::PortNumber(3000))
            ->onConnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const std::unordered_map<std::string, std::string> &header) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");
            })
            ->onMessage([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const SL::WS_LITE::WSMessage &message) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL::WS_LITE::WSMessage msg;
                msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char *p) { delete[] p; });
                msg.len = message.len;
                msg.code = message.code;
                msg.data = msg.Buffer.get();
                memcpy(msg.data, message.data, message.len);
                socket->send(msg, SL::WS_LITE::CompressionOptions::NO_COMPRESSION);
            })
            ->listen();

    listener->set_ReadTimeout(std::chrono::seconds(100));
    listener->set_WriteTimeout(std::chrono::seconds(100));

    auto tlslistener =
        SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(1))
            ->UseTLS(
                [](SL::WS_LITE::ITLSContext *context) {
                    context->set_options(SL::WS_LITE::options::default_workarounds | SL::WS_LITE::options::no_sslv2 | SL::WS_LITE::options::no_sslv3 |
                                         SL::WS_LITE::options::single_dh_use);
                    std::error_code ec;

                    context->set_password_callback(
                        [](std::size_t s, SL::WS_LITE::password_purpose p) { return std::string(TEST_CERTIFICATE_PRIVATE_PASSWORD); }, ec);
                    if (ec) {
                        std::cout << "set_password_callback failed: " << ec.message();
                        ec.clear();
                    }
                    context->use_tmp_dh_file(std::string(TEST_DH_PATH), ec);
                    if (ec) {
                        std::cout << "use_tmp_dh_file failed: " << ec.message();
                        ec.clear();
                    }
                    context->use_certificate_chain_file(std::string(TEST_CERTIFICATE_PUBLIC_PATH), ec);
                    if (ec) {
                        std::cout << "use_certificate_chain_file failed: " << ec.message();
                        ec.clear();
                    }
                    context->set_default_verify_paths(ec);
                    if (ec) {
                        std::cout << "set_default_verify_paths failed: " << ec.message();
                        ec.clear();
                    }
                    context->use_private_key_file(std::string(TEST_CERTIFICATE_PRIVATE_PATH), SL::WS_LITE::file_format::pem, ec);
                    if (ec) {
                        std::cout << "use_private_key_file failed: " << ec.message();
                        ec.clear();
                    }
                },
                SL::WS_LITE::method::tlsv11)
            ->CreateListener(SL::WS_LITE::PortNumber(3001))
            ->onConnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const std::unordered_map<std::string, std::string> &header) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "tlslistener::onConnection");
            })
            ->onMessage([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const SL::WS_LITE::WSMessage &message) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL::WS_LITE::WSMessage msg;
                msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char *p) { delete[] p; });
                msg.len = message.len;
                msg.code = message.code;
                msg.data = msg.Buffer.get();
                memcpy(msg.data, message.data, message.len);
                socket->send(msg, SL::WS_LITE::CompressionOptions::NO_COMPRESSION);
            })
            ->listen();

    tlslistener->set_ReadTimeout(std::chrono::seconds(100));
    tlslistener->set_WriteTimeout(std::chrono::seconds(100));

    std::string cmd = "wstest -m fuzzingclient -s ";
    cmd += TEST_FUZZING_PATH;
    system(cmd.c_str());
    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 2000) {
        std::this_thread::sleep_for(200ms);
    }
    std::cout << "Exiting autobahn test..." << std::endl;
}
void generaltest()
{
    std::cout << "Starting General test..." << std::endl;
    auto lastheard = std::chrono::high_resolution_clock::now();

    SL::WS_LITE::PortNumber port(3002);
    auto listenerctx =
        SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(1))
            ->NoTLS()
            ->CreateListener(port)
            ->onConnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const std::unordered_map<std::string, std::string> &header) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");

            })
            ->onMessage([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const SL::WS_LITE::WSMessage &message) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL::WS_LITE::WSMessage msg;
                msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char *p) { delete[] p; });
                msg.len = message.len;
                msg.code = message.code;
                msg.data = msg.Buffer.get();
                memcpy(msg.data, message.data, message.len);
                socket->send(msg, SL::WS_LITE::CompressionOptions::NO_COMPRESSION);
            })
            ->onDisconnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, unsigned short code, const std::string &msg) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onDisconnection");
            })
            ->listen();

    auto clientctx =
        SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(1))
            ->NoTLS()
            ->CreateClient()
            ->onConnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const std::unordered_map<std::string, std::string> &header) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onConnection");
            })
            ->onDisconnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, unsigned short code, const std::string &msg) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "client::onDisconnection");
            })
            ->connect("localhost", port);

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 2000) {
        std::this_thread::sleep_for(200ms);
    }
}
void generalTLStest()
{
    std::cout << "Starting General TLS test..." << std::endl;
    auto lastheard = std::chrono::high_resolution_clock::now();
    SL::WS_LITE::PortNumber port(3005);
    auto listenerctx =
        SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(1))
            ->UseTLS(
                [](SL::WS_LITE::ITLSContext *context) {
                    context->set_options(SL::WS_LITE::options::default_workarounds | SL::WS_LITE::options::no_sslv2 | SL::WS_LITE::options::no_sslv3 |
                                         SL::WS_LITE::options::single_dh_use);
                    std::error_code ec;

                    context->set_password_callback(
                        [](std::size_t s, SL::WS_LITE::password_purpose p) { return std::string(TEST_CERTIFICATE_PRIVATE_PASSWORD); }, ec);
                    if (ec) {
                        std::cout << "set_password_callback failed: " << ec.message();
                        ec.clear();
                    }
                    context->use_tmp_dh_file(std::string(TEST_DH_PATH), ec);
                    if (ec) {
                        std::cout << "use_tmp_dh_file failed: " << ec.message();
                        ec.clear();
                    }
                    context->use_certificate_chain_file(std::string(TEST_CERTIFICATE_PUBLIC_PATH), ec);
                    if (ec) {
                        std::cout << "use_certificate_chain_file failed: " << ec.message();
                        ec.clear();
                    }
                    context->set_default_verify_paths(ec);
                    if (ec) {
                        std::cout << "set_default_verify_paths failed: " << ec.message();
                        ec.clear();
                    }
                    context->use_private_key_file(std::string(TEST_CERTIFICATE_PRIVATE_PATH), SL::WS_LITE::file_format::pem, ec);
                    if (ec) {
                        std::cout << "use_private_key_file failed: " << ec.message();
                        ec.clear();
                    }
                },
                SL::WS_LITE::method::tlsv11)
            ->CreateListener(port)
            ->onConnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const std::unordered_map<std::string, std::string> &header) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onConnection");

            })
            ->onMessage([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const SL::WS_LITE::WSMessage &message) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL::WS_LITE::WSMessage msg;
                msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char *p) { delete[] p; });
                msg.len = message.len;
                msg.code = message.code;
                msg.data = msg.Buffer.get();
                memcpy(msg.data, message.data, message.len);
                socket->send(msg, SL::WS_LITE::CompressionOptions::NO_COMPRESSION);
            })
            ->onDisconnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, unsigned short code, const std::string &msg) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "listener::onDisconnection");
            })
            ->listen();

    auto clientctx =
        SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(1))
            ->UseTLS(
                [](SL::WS_LITE::ITLSContext *context) {

                    std::ifstream file(TEST_CERTIFICATE_PUBLIC_PATH, std::ios::binary);
                    assert(file);
                    std::vector<char> buf;
                    buf.resize(static_cast<size_t>(filesize(TEST_CERTIFICATE_PUBLIC_PATH)));
                    file.read(buf.data(), buf.size());
                    std::error_code ec;
                    context->add_certificate_authority(reinterpret_cast<unsigned char *>(buf.data()), buf.size(), ec);
                    if (ec) {
                        std::cout << "add_certificate_authority failed: " << ec.message();
                        ec.clear();
                    }
                    context->set_default_verify_paths(ec);
                    if (ec) {
                        std::cout << "set_default_verify_paths failed: " << ec.message();
                        ec.clear();
                    }
                },
                SL::WS_LITE::method::tlsv11)
            ->CreateClient()
            ->onConnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const std::unordered_map<std::string, std::string> &header) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "Client::onConnection");
            })
            ->onDisconnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, unsigned short code, const std::string &msg) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL_WS_LITE_LOG(SL::WS_LITE::Logging_Levels::INFO_log_level, "client::onDisconnection");
            })
            ->connect("localhost", port);

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 2000) {
        std::this_thread::sleep_for(200ms);
    }
    std::this_thread::sleep_for(200ms);
}

void multithreadtest()
{
    std::cout << "Starting Multi threaded test..." << std::endl;
    auto lastheard = std::chrono::high_resolution_clock::now();

    SL::WS_LITE::PortNumber port(3003);
    auto listenerctx =
        SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(2))
            ->NoTLS()
            ->CreateListener(port)
            ->onConnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const std::unordered_map<std::string, std::string> &header) {
                lastheard = std::chrono::high_resolution_clock::now();
            })
            ->onDisconnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, unsigned short code, const std::string &msg) {
                lastheard = std::chrono::high_resolution_clock::now();
            })
            ->onMessage([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const SL::WS_LITE::WSMessage &message) {
                lastheard = std::chrono::high_resolution_clock::now();
                SL::WS_LITE::WSMessage msg;
                msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[message.len], [](unsigned char *p) { delete[] p; });
                msg.len = message.len;
                msg.code = message.code;
                msg.data = msg.Buffer.get();
                memcpy(msg.data, message.data, message.len);
                socket->send(msg, SL::WS_LITE::CompressionOptions::NO_COMPRESSION);
            })
            ->listen();

    std::vector<std::shared_ptr<SL::WS_LITE::IWSHub>> clients;
    auto clientctx(SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(2)));
    clients.reserve(50);
    for (auto i = 0; i < 50; i++) {
        auto c = clientctx->NoTLS()
                     ->CreateClient()
                     ->onConnection([&lastheard, i](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket,
                                                    const std::unordered_map<std::string, std::string> &header) {
                         lastheard = std::chrono::high_resolution_clock::now();
                         SL::WS_LITE::WSMessage msg;
                         std::string txtmsg = "testing msg";
                         txtmsg += std::to_string(i);
                         msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[txtmsg.size()], [](unsigned char *p) { delete[] p; });
                         msg.len = txtmsg.size();
                         msg.code = SL::WS_LITE::OpCode::TEXT;
                         msg.data = msg.Buffer.get();
                         memcpy(msg.data, txtmsg.data(), txtmsg.size());
                         socket->send(msg, SL::WS_LITE::CompressionOptions::NO_COMPRESSION);
                     })
                     ->onDisconnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, unsigned short code, const std::string &msg) {
                         lastheard = std::chrono::high_resolution_clock::now();
                     })
                     ->onMessage([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const SL::WS_LITE::WSMessage &message) {
                         lastheard = std::chrono::high_resolution_clock::now();
                     })
                     ->connect("localhost", port);
        clients.push_back(c);
    }

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 2000) {
        std::this_thread::sleep_for(200ms);
    }
}
const auto bufferesize = 1024 * 1024 * 10;
void multithreadthroughputtest()
{
    std::cout << "Starting Multi threaded throughput test" << std::endl;
    std::vector<std::shared_ptr<SL::WS_LITE::IWSHub>> clients;
    clients.reserve(50); // this should use about 1 GB of memory between sending and receiving
    auto recvtimer = std::chrono::high_resolution_clock::now();
    auto lastheard = std::chrono::high_resolution_clock::now();
    std::atomic<unsigned long long> mbsreceived;
    mbsreceived = 0;

    SL::WS_LITE::PortNumber port(3004);
    auto listenerctx =
        SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(2))
            ->NoTLS()
            ->CreateListener(port)
            ->onConnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const std::unordered_map<std::string, std::string> &header) {
                lastheard = std::chrono::high_resolution_clock::now();
            })
            ->onDisconnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, unsigned short code, const std::string &msg) {
                lastheard = std::chrono::high_resolution_clock::now();
            })
            ->onMessage([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const SL::WS_LITE::WSMessage &message) {
                lastheard = std::chrono::high_resolution_clock::now();
                mbsreceived += message.len;
                if (mbsreceived == bufferesize * clients.capacity()) {
                    std::cout << "Took "
                              << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - recvtimer).count()
                              << "ms to receive " << bufferesize * clients.capacity() << " bytes" << std::endl;
                }
            })
            ->listen();

    std::atomic<unsigned long long> mbssent;
    mbssent = 0;

    auto clientctx = SL::WS_LITE::CreateContext(SL::WS_LITE::ThreadCount(2));
    auto sendtimer = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < clients.capacity(); i++) {
        auto c =
            clientctx->NoTLS()
                ->CreateClient()
                ->onConnection([&clients, &lastheard, &mbssent, &sendtimer](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket,
                                                                            const std::unordered_map<std::string, std::string> &header) {
                    lastheard = std::chrono::high_resolution_clock::now();
                    SL::WS_LITE::WSMessage msg;
                    msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[bufferesize], [&](unsigned char *p) {
                        mbssent += bufferesize;
                        if (mbssent == bufferesize * clients.capacity()) {
                            std::cout << "Took "
                                      << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - sendtimer)
                                             .count()
                                      << "ms to send " << bufferesize * clients.capacity() << " bytes" << std::endl;
                        }
                        delete[] p;
                    });
                    msg.len = bufferesize; // 10MB
                    msg.code = SL::WS_LITE::OpCode::BINARY;
                    msg.data = msg.Buffer.get();
                    socket->send(msg, SL::WS_LITE::CompressionOptions::NO_COMPRESSION);
                })
                ->onDisconnection([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, unsigned short code, const std::string &msg) {
                    lastheard = std::chrono::high_resolution_clock::now();
                })
                ->onMessage([&](const std::shared_ptr<SL::WS_LITE::IWSocket> &socket, const SL::WS_LITE::WSMessage &message) {
                    lastheard = std::chrono::high_resolution_clock::now();
                })
                ->connect("localhost", port);
        clients.push_back(c);
    }
    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - lastheard).count() < 5000) {
        std::this_thread::sleep_for(200ms);
    }
    std::this_thread::sleep_for(200ms);
    std::cout << "Received " << mbsreceived << "  bytes" << std::endl;
}
#include <sstream>
void checkexpected(std::unordered_map<std::string, std::string> &header, std::string key, std::string expectedvalue)
{
    auto t = header.find(key);
    if (t != header.end()) {
        assert(t->second == expectedvalue);
    }
}
void testfirstlineprasing()
{
    {
        SL::WS_LITE::HttpHeader header;
        SL::WS_LITE::ParseFirstLine("GET /chat HTTP/1.1", header);
        assert(header.Verb == SL::WS_LITE::HttpVerbs::GET);
        assert(header.UrlPart == "/chat");
        assert(header.HttpVersion == SL::WS_LITE::HttpVersions::HTTP1_1);
    }

    {
        SL::WS_LITE::HttpHeader header1;
        SL::WS_LITE::ParseFirstLine("/ HTTP/1.5", header1);
        assert(header1.Verb == SL::WS_LITE::HttpVerbs::UNDEFINED);
        assert(header1.UrlPart == "/");
        assert(header1.HttpVersion == SL::WS_LITE::HttpVersions::UNDEFINED);
    }

    {
        SL::WS_LITE::HttpHeader header2;
        SL::WS_LITE::ParseFirstLine("", header2);
        assert(header2.Verb == SL::WS_LITE::HttpVerbs::UNDEFINED);
        assert(header2.UrlPart.empty());
        assert(header2.HttpVersion == SL::WS_LITE::HttpVersions::UNDEFINED);
    }

    {
        SL::WS_LITE::HttpHeader header3;
        SL::WS_LITE::ParseFirstLine("  GET   /chat   HTTP/1.1  ", header3);
        assert(header3.Verb == SL::WS_LITE::HttpVerbs::GET);
        assert(header3.UrlPart == "/chat");
        assert(header3.HttpVersion == SL::WS_LITE::HttpVersions::HTTP1_1);
    }

    {
        SL::WS_LITE::HttpHeader header4;
        SL::WS_LITE::ParseFirstLine(" jibbger jaber  ", header4);
        assert(header4.Verb == SL::WS_LITE::HttpVerbs::UNDEFINED);
        assert(header4.UrlPart.empty());
        assert(header4.HttpVersion == SL::WS_LITE::HttpVersions::UNDEFINED);
    }

    {
        SL::WS_LITE::HttpHeader header5;
        SL::WS_LITE::ParseFirstLine(" HTTP/2.0 200 OK", header5);
        assert(header5.Verb == SL::WS_LITE::HttpVerbs::UNDEFINED);
        assert(header5.UrlPart.empty());
        assert(header5.Code == 200);
        assert(header5.HttpVersion == SL::WS_LITE::HttpVersions::HTTP2_0);
    }
}
void testkeyvalueparsing()
{
    {
        auto keyvalue = SL::WS_LITE::ParseKeyValue("Cache-Control:no-cache");
        assert(keyvalue.Key == "Cache-Control");
        assert(keyvalue.Value == "no-cache");
    }
    {
        auto keyvalue = SL::WS_LITE::ParseKeyValue("Accept-Encoding:gzip, deflate");
        assert(keyvalue.Key == "Accept-Encoding");
        assert(keyvalue.Value == "gzip, deflate");
    }
    {
        auto keyvalue = SL::WS_LITE::ParseKeyValue("  Accept-Encoding  :  gzip, deflate   ");
        assert(keyvalue.Key == "Accept-Encoding");
        assert(keyvalue.Value == "gzip, deflate");
    }
}
void testrequestheaderparsing()
{

    std::unordered_map<std::string, std::string> header;

    std::string str = "Accept-Encoding:gzip, deflate";
    str += "Accept-Language:en-US,en;q=0.9";
    str += "Cache-Control:no-cache";
    str += "Connection:Upgrade";
    str += "Host:echo.websocket.org";
    str += "Origin:http://www.websocket.org";
    str += "Pragma:no-cache";
    str += "Sec-WebSocket-Extensions:permessage-deflate; client_max_window_bits";
    str += "Sec-WebSocket-Key:itOii17PhfRYwRkJJgPMwA==";
    str += "SSec-WebSocket-Version:13";
    std::istringstream handshake(str);

    assert(SL::WS_LITE::Parse_ClientHandshake(handshake, header));
    checkexpected(header, "Accept-Encoding", "gzip, deflate");
    checkexpected(header, "Accept-Language", "en-US,en;q=0.9");
    checkexpected(header, "Accept-Language", "en-US,en;q=0.9");
    checkexpected(header, "Connection", "Upgrade");
    checkexpected(header, "Pragma", "no-cache");
}
void testresponseheaderparsing()
{

    std::unordered_map<std::string, std::string> header;
    std::string str = "GET /chat HTTP/1.1";
    str += "Host: server.example.com";
    str += "Upgrade: websocket";
    str += "Connection:Upgrade";
    str += "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==";
    str += "Origin:http://www.websocket.org";
    str += "Sec-WebSocket-Protocol: chat, superchat";
    str += "Sec-WebSocket-Version: 13";

    std::istringstream handshake1(str);
}

int main(int argc, char *argv[])
{
    testfirstlineprasing();
    testkeyvalueparsing();
    // testheaderparsing();
    /*   wssautobahntest();
       std::this_thread::sleep_for(1s);
       generaltest();
       std::this_thread::sleep_for(1s);
       generalTLStest();
       std::this_thread::sleep_for(1s);
       multithreadtest();
       std::this_thread::sleep_for(1s);
       multithreadthroughputtest();*/
    return 0;
}
