#pragma once
#include "Logging.h"
#include "WS_Lite.h"
#include <chrono>
#include <functional>
#include <memory>
#include <string.h>
#include <zlib.h>
namespace SL {
namespace WS_LITE {
    const size_t LARGE_BUFFER_SIZE = 4 * 1024 * 1024; // 4 MB temp buffer
    class IWebSocket;
    struct HttpHeader;
    struct WSMessage;
    class WebSocketContext {
        unsigned char *InflateBuffer = nullptr;
        size_t InflateBufferSize = 0;
        std::unique_ptr<unsigned char[]> TempInflateBuffer;
        z_stream InflationStream = {};
        auto returnemptyinflate()
        {
            unsigned char *p = nullptr;
            size_t o = 0;
            return std::make_tuple(p, o);
        }

      public:
        WebSocketContext()
        {
            TempInflateBuffer = std::make_unique<unsigned char[]>(MaxPayload);
            inflateInit2(&InflationStream, -MAX_WBITS);
        }
        ~WebSocketContext() { inflateEnd(&InflationStream); }
        auto beginInflate()
        {
            InflateBufferSize = 0;
            free(InflateBuffer);
            InflateBuffer = nullptr;
        }
        auto Inflate(unsigned char *data, size_t data_len)
        {
            InflationStream.next_in = (Bytef *)data;
            InflationStream.avail_in = data_len;

            int err;
            do {
                InflationStream.next_out = (Bytef *)TempInflateBuffer.get();
                InflationStream.avail_out = LARGE_BUFFER_SIZE;
                err = ::inflate(&InflationStream, Z_FINISH);
                if (!InflationStream.avail_in) {
                    break;
                }
                auto growsize = LARGE_BUFFER_SIZE - InflationStream.avail_out;
                InflateBufferSize += growsize;
                auto beforesize = InflateBufferSize;
                InflateBuffer = static_cast<unsigned char *>(realloc(InflateBuffer, InflateBufferSize));
                if (!InflateBuffer) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "INFLATE MEMORY ALLOCATION ERROR!!! Tried to realloc " << InflateBufferSize);
                    return returnemptyinflate();
                }
                memcpy(InflateBuffer + beforesize, TempInflateBuffer.get(), growsize);
            } while (err == Z_BUF_ERROR && InflateBufferSize <= MaxPayload);

            inflateReset(&InflationStream);

            if ((err != Z_BUF_ERROR && err != Z_OK) || InflateBufferSize > MaxPayload) {
                return returnemptyinflate();
            }
            if (InflateBufferSize > 0) {
                auto growsize = LARGE_BUFFER_SIZE - InflationStream.avail_out;
                InflateBufferSize += growsize;
                auto beforesize = InflateBufferSize;
                InflateBuffer = static_cast<unsigned char *>(realloc(InflateBuffer, InflateBufferSize));
                if (!InflateBuffer) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "INFLATE MEMORY ALLOCATION ERROR!!! Tried to realloc " << InflateBufferSize);
                    return returnemptyinflate();
                }
                memcpy(InflateBuffer + beforesize, TempInflateBuffer.get(), growsize);
                return std::make_tuple(InflateBuffer, InflateBufferSize);
            }
            return std::make_tuple(TempInflateBuffer.get(), LARGE_BUFFER_SIZE - (size_t)InflationStream.avail_out);
        }
        auto endInflate() { beginInflate(); }
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