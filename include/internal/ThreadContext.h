#pragma once
#if WIN32
#include <SDKDDKVer.h>
#endif
#include "WebSocketContext.h"
#include "asio.hpp"
#include "asio/ssl.hpp"
#include <thread>

namespace SL {
namespace WS_LITE {

    struct ThreadContext {
        ThreadContext(asio::ssl::context_base::method m = asio::ssl::context_base::method::tlsv12)
            : work(io_service), context(m), WebSocketContext_(std::make_shared<WebSocketContext>())
        {
            thread = std::thread([&] {
                std::error_code ec;
                io_service.run(ec);
            });
        }

        std::thread thread;
        asio::io_service io_service;
        asio::io_service::work work;
        asio::ssl::context context;
        std::shared_ptr<WebSocketContext> WebSocketContext_;
    };

} // namespace WS_LITE
} // namespace SL