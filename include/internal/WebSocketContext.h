#pragma once
#include "Logging.h"
#include "WS_Lite.h"
#include <chrono>
#include <functional>
#include <memory>
#include <zlib.h>

namespace SL {
namespace WS_LITE {
    const size_t LARGE_BUFFER_SIZE = 300 * 1024;
    class IWebSocket;
    struct HttpHeader;
    struct WSMessage;
    struct WebSocketContext {

        WebSocketContext() : inflationBuffer(std::make_unique<char[]>(LARGE_BUFFER_SIZE)) { inflateInit2(&inflationStream, -MAX_WBITS); }
        ~WebSocketContext() { inflateEnd(&inflationStream); }
        auto inflate(unsigned char *data, size_t data_len)
        {
            dynamicInflationBuffer.clear();
            inflationStream.next_in = (Bytef *)data;
            inflationStream.avail_in = data_len;

            int err;
            do {
                inflationStream.next_out = (Bytef *)inflationBuffer.get();
                inflationStream.avail_out = LARGE_BUFFER_SIZE;
                err = ::inflate(&inflationStream, Z_FINISH);
                if (!inflationStream.avail_in) {
                    break;
                }

                dynamicInflationBuffer.append(inflationBuffer.get(), LARGE_BUFFER_SIZE - inflationStream.avail_out);
            } while (err == Z_BUF_ERROR && dynamicInflationBuffer.length() <= MaxPayload);

            inflateReset(&inflationStream);

            if ((err != Z_BUF_ERROR && err != Z_OK) || dynamicInflationBuffer.length() > MaxPayload) {
                unsigned char *p = nullptr;
                size_t o = 0;
                return std::make_tuple(p, o);
            }
            if (!dynamicInflationBuffer.empty()) {
                dynamicInflationBuffer.append(inflationBuffer.get(), LARGE_BUFFER_SIZE - inflationStream.avail_out);
                return std::make_tuple((unsigned char *)dynamicInflationBuffer.data(), dynamicInflationBuffer.length());
            }

            return std::make_tuple((unsigned char *)inflationBuffer.get(), LARGE_BUFFER_SIZE - (size_t)inflationStream.avail_out);
        }
        std::string dynamicInflationBuffer;
        std::unique_ptr<char[]> inflationBuffer;
        z_stream inflationStream = {};

        std::function<void(const std::shared_ptr<IWebSocket> &, const HttpHeader &)> onConnection;
        std::function<void(const std::shared_ptr<IWebSocket> &, const WSMessage &)> onMessage;
        std::function<void(const std::shared_ptr<IWebSocket> &, unsigned short, const std::string &)> onDisconnection;
        std::function<void(const std::shared_ptr<IWebSocket> &, const unsigned char *, size_t)> onPing;
        std::function<void(const std::shared_ptr<IWebSocket> &, const unsigned char *, size_t)> onPong;

        std::chrono::seconds WriteTimeout = std::chrono::seconds(30);
        std::chrono::seconds ReadTimeout = std::chrono::seconds(30);
        size_t MaxPayload = 1024 * 1024 * 20; // 20 MB

        ExtensionOptions ExtensionOptions_ = ExtensionOptions::NO_OPTIONS;
    };
} // namespace WS_LITE
} // namespace SL