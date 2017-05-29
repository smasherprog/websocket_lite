#pragma once
#include "WS_Lite.h"
#include "Utils.h"
#include "Logging.h"

#if WIN32
#include <SDKDDKVer.h>
#endif

#include <string>
#include <unordered_map>
#include <memory>
#include <thread>
#include <deque>

#include "asio.hpp"
#include "asio/ssl.hpp"
#include "asio/deadline_timer.hpp"


namespace SL {
    namespace WS_LITE {

        struct HandshakeContainer {
            asio::streambuf Read;
            asio::streambuf Write;
            std::unordered_map<std::string, std::string> Header;
        };
        struct WSSendMessageInternal {
            unsigned char* data;
            size_t len;
            OpCode code;
            //compress the outgoing message?
            bool Compress;
        };


        struct SendQueueItem {
            WSMessage msg;
            bool compressmessage;
        };
        struct WSocketImpl
        {
            WSocketImpl(asio::io_service& s) :read_deadline(s), write_deadline(s), strand(s) {}
            ~WSocketImpl() {
                canceltimers();
                if (ReceiveBuffer) {
                    free(ReceiveBuffer);
                }
            }
            asio::basic_waitable_timer<std::chrono::steady_clock> read_deadline;
            asio::basic_waitable_timer<std::chrono::steady_clock> write_deadline;
            unsigned char* ReceiveBuffer = nullptr;
            size_t ReceiveBufferSize = 0;
            unsigned char ReceiveHeader[14];
            bool CompressionEnabled = false;

            OpCode LastOpCode = OpCode::INVALID;
            std::shared_ptr<asio::ip::tcp::socket> Socket;
            std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> TLSSocket;
            asio::strand strand;
            std::deque<SendQueueItem> SendMessageQueue;

            void canceltimers() {
                read_deadline.cancel();
                write_deadline.cancel();
            }
        };
        inline void set_Socket(std::shared_ptr<WSocketImpl>& ws, std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> s) {
            ws->TLSSocket = s;
        }
        inline void set_Socket(std::shared_ptr<WSocketImpl>& ws, std::shared_ptr<asio::ip::tcp::socket>  s) {
            ws->Socket = s;
        }


        struct ThreadContext {
            std::unique_ptr<char[]> inflationBuffer;
            z_stream inflationStream = {};
            std::thread Thread;
        };
        const auto CONTROLBUFFERMAXSIZE = 125;
        class WSContextImpl {
        public:
            WSContextImpl(ThreadCount threadcount) : work(std::make_unique<asio::io_service::work>(io_service)) {
                Threads.resize(threadcount.value);
                for (auto& ctx : Threads) {
                    inflateInit2(&ctx.inflationStream, -MAX_WBITS);
                    ctx.inflationBuffer = std::make_unique<char[]>(LARGE_BUFFER_SIZE);
                    ctx.Thread = std::thread([&]() {
                        std::error_code ec;
                        io_service.run(ec);
                    });
                }
            }
            ~WSContextImpl() {
                work.reset();
                io_service.stop();
                while (!io_service.stopped()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                for (auto& t : Threads) {
                    inflateEnd(&t.inflationStream);
                    if (t.Thread.joinable()) {
                        t.Thread.join();
                    }
                }
                Threads.clear();
            }

            asio::io_service io_service;
            std::vector<ThreadContext> Threads;
            std::unique_ptr<asio::io_service::work> work;

        };

        struct WSInternal {
            WSInternal(std::shared_ptr<WSContextImpl>& p) :WSContextImpl_(p), sslcontext(asio::ssl::context::tlsv11) {}
            std::shared_ptr<WSContextImpl> WSContextImpl_;
            asio::ssl::context sslcontext;
            std::chrono::seconds ReadTimeout = std::chrono::seconds(30);
            std::chrono::seconds WriteTimeout = std::chrono::seconds(30);
            size_t MaxPayload = 1024 * 1024 * 20;//20 MB
            bool TLSEnabled = false;

            std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)> onConnection;
            std::function<void(WSocket&, const WSMessage&)> onMessage;
            std::function<void(WSocket&, unsigned short, const std::string&)> onDisconnection;
            std::function<void(WSocket&, const unsigned char *, size_t)> onPing;
            std::function<void(WSocket&, const unsigned char *, size_t)> onPong;
            std::function<void(WSocket&)> onHttpUpgrade;

        };



        class WSClientImpl : public WSInternal {
        public:
            WSClientImpl(std::shared_ptr<WSContextImpl>& p, std::string Publiccertificate_File) : WSClientImpl(p)
            {
                TLSEnabled = true;
                std::ifstream file(Publiccertificate_File, std::ios::binary);
                assert(file);
                std::vector<char> buf;
                buf.resize(static_cast<size_t>(filesize(Publiccertificate_File)));
                file.read(buf.data(), buf.size());
                asio::const_buffer cert(buf.data(), buf.size());
                std::error_code ec;
                sslcontext.add_certificate_authority(cert, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "add_certificate_authority " << ec.message());
                    ec.clear();
                }
                sslcontext.set_default_verify_paths(ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "set_default_verify_paths " << ec.message());
                    ec.clear();
                }
                add_other_root_certs(sslcontext);
            }        
            WSClientImpl(std::shared_ptr<WSContextImpl>& p, bool dummyargtoenabletls) : WSClientImpl(p)
            {
                UNUSED(dummyargtoenabletls);
                TLSEnabled = true;
                std::error_code ec;
                sslcontext.set_default_verify_paths(ec);
                add_other_root_certs(sslcontext);
            }
            WSClientImpl(std::shared_ptr<WSContextImpl>& p) :WSInternal(p)
            {
            }
            ~WSClientImpl() {}
        };

        class WSListenerImpl : public WSInternal {
        public:

            asio::ip::tcp::acceptor acceptor;

            WSListenerImpl(
                std::shared_ptr<WSContextImpl>& p,
                PortNumber port,
                std::string Password,
                std::string Privatekey_File,
                std::string Publiccertificate_File,
                std::string dh_File) :
                WSListenerImpl(p, port)
            {
                TLSEnabled = true;
                sslcontext.set_options(
                    asio::ssl::context::default_workarounds
                    | asio::ssl::context::no_sslv2 | asio::ssl::context::no_sslv3
                    | asio::ssl::context::single_dh_use);
                std::error_code ec;
                sslcontext.set_password_callback([Password](std::size_t, asio::ssl::context::password_purpose) { return Password; }, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "set_password_callback " << ec.message());
                    ec.clear();
                }
                sslcontext.use_tmp_dh_file(dh_File, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "use_tmp_dh_file " << ec.message());
                    ec.clear();
                }
                sslcontext.use_certificate_chain_file(Publiccertificate_File, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "use_certificate_chain_file " << ec.message());
                    ec.clear();
                }
                sslcontext.set_default_verify_paths(ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "set_default_verify_paths " << ec.message());
                    ec.clear();
                }
                sslcontext.use_private_key_file(Privatekey_File, asio::ssl::context::pem, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "use_private_key_file " << ec.message());
                    ec.clear();
                }
                add_other_root_certs(sslcontext);
            }

            WSListenerImpl(std::shared_ptr<WSContextImpl>& p, PortNumber port) :
                WSInternal(p),
                acceptor(p->io_service, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port.value)) {

            }

            ~WSListenerImpl() {
                std::error_code ec;
                acceptor.close(ec);
            }
        };
    }
}