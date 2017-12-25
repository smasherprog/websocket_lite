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
    static const int LARGE_BUFFER_SIZE = 300 * 1024;
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
        std::unique_ptr<char[]> inflationBuffer;
        z_stream inflationStream = {};
        std::thread thread;
        asio::io_service io_service;
        asio::io_service::work work;
        asio::ssl::context context;
    };

} // namespace WS_LITE
} // namespace SL