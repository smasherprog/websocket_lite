#pragma once
#if WIN32
#include <SDKDDKVer.h>
#endif
#include "asio.hpp"
#include "asio/ssl.hpp"
#include <thread>
#include <zlib.h>

namespace SL {
namespace WS_LITE {
    class IWSocket;
    struct HttpHeader;
    struct WSMessage;
    const size_t LARGE_BUFFER_SIZE = 300 * 1024;
    struct ThreadContext {
        ThreadContext(asio::ssl::context_base::method m = asio::ssl::context_base::method::tlsv12)
            : work(io_service), context(m), inflationBuffer(std::make_unique<char[]>(LARGE_BUFFER_SIZE))
        {
            inflateInit2(&inflationStream, -MAX_WBITS);
            thread = std::thread([&] {
                std::error_code ec;
                io_service.run(ec);
            });
        }

        auto inflate(char *data, size_t length, size_t maxPayload)
        {
            dynamicInflationBuffer.clear();
            inflationStream.next_in = (Bytef *)data;
            inflationStream.avail_in = length;

            int err;
            do {
                inflationStream.next_out = (Bytef *)inflationBuffer.get();
                inflationStream.avail_out = LARGE_BUFFER_SIZE;
                err = ::inflate(&inflationStream, Z_FINISH);
                if (!inflationStream.avail_in) {
                    break;
                }

                dynamicInflationBuffer.append(inflationBuffer.get(), LARGE_BUFFER_SIZE - inflationStream.avail_out);
            } while (err == Z_BUF_ERROR && dynamicInflationBuffer.length() <= maxPayload);

            inflateReset(&inflationStream);

            if ((err != Z_BUF_ERROR && err != Z_OK) || dynamicInflationBuffer.length() > maxPayload) {
                unsigned char *p = nullptr;
                size_t o = 0;
                return std::make_tuple(p, o);
            }

            if (dynamicInflationBuffer.length()) {
                dynamicInflationBuffer.append(inflationBuffer.get(), LARGE_BUFFER_SIZE - inflationStream.avail_out);
                return std::make_tuple((unsigned char *)dynamicInflationBuffer.data(), dynamicInflationBuffer.length());
            }

            return std::make_tuple((unsigned char *)inflationBuffer.get(), LARGE_BUFFER_SIZE - (size_t)inflationStream.avail_out);
        }
        std::string dynamicInflationBuffer;
        std::unique_ptr<char[]> inflationBuffer;
        z_stream inflationStream = {};
        std::thread thread;
        asio::io_service io_service;
        asio::io_service::work work;
        asio::ssl::context context;

        std::function<void(const std::shared_ptr<IWSocket> &, const HttpHeader &)> onConnection;
        std::function<void(const std::shared_ptr<IWSocket> &, const WSMessage &)> onMessage;
        std::function<void(const std::shared_ptr<IWSocket> &, unsigned short, const std::string &)> onDisconnection;
        std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> onPing;
        std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> onPong;

        std::chrono::seconds WriteTimeout = std::chrono::seconds(30);
        std::chrono::seconds ReadTimeout = std::chrono::seconds(30);
        size_t MaxPayload = 1024 * 1024 * 20; // 20 MB
        bool TLSEnabled = false;
        ExtensionOptions ExtensionOptions_ = ExtensionOptions::NO_OPTIONS;
    };

} // namespace WS_LITE
} // namespace SL