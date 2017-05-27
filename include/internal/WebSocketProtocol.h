#pragma once
#include "WS_Lite.h"
#include "DataStructures.h"
#include "Utils.h"
#if WIN32
#include <SDKDDKVer.h>
#endif

#include <string>
#include <unordered_map>
#include <memory>
#include <random>
#include <deque>

#include "asio.hpp"
#include "asio/ssl.hpp"
#include "asio/deadline_timer.hpp"

namespace SL {
    namespace WS_LITE {


        template<class PARENTTYPE, class SOCKETTYPE> void readexpire_from_now(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, std::chrono::seconds secs)
        {

            std::error_code ec;
            if (secs.count() <= 0) websocket->read_deadline.cancel(ec);
            else  websocket->read_deadline.expires_from_now(secs, ec);
            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
            }
            else if (secs.count() >= 0) {
                websocket->read_deadline.async_wait([parent, websocket, socket](const std::error_code& ec) {
                    if (ec != asio::error::operation_aborted) {
                        return closeImpl(parent, websocket, 1001, "read timer expired on the socket ");
                    }
                });
            }
        }
        template<class PARENTTYPE, class SOCKETTYPE> void writeexpire_from_now(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, std::chrono::seconds secs)
        {
            std::error_code ec;
            if (secs.count() <= 0) websocket->write_deadline.cancel(ec);
            else websocket->write_deadline.expires_from_now(secs, ec);
            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
            }
            else if (secs.count() >= 0) {
                websocket->write_deadline.async_wait([parent, websocket, socket](const std::error_code& ec) {
                    if (ec != asio::error::operation_aborted) {
                        return closeImpl(parent, websocket, 1001, "write timer expired on the socket ");
                    }
                });
            }
        }
        template<class PARENTTYPE>inline void startwrite(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket) {
            if (!websocket->SendMessageQueue.empty()) {
                auto msg(websocket->SendMessageQueue.front());
                if (websocket->Socket) {
                    write(parent, websocket, websocket->Socket, msg.msg);
                }
                else {
                    write(parent, websocket, websocket->TLSSocket, msg.msg);
                }
            }
        }
        template<class PARENTTYPE>void sendImpl(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, WSMessage& msg, bool compressmessage) {
            if (compressmessage) {
                assert(msg.code == OpCode::BINARY || msg.code == OpCode::TEXT);
            }
            websocket->strand.post([websocket, msg, parent, compressmessage]() {
                websocket->SendMessageQueue.emplace_back(SendQueueItem{ msg, compressmessage });
                if (websocket->SendMessageQueue.size() == 1) {
                    SL::WS_LITE::startwrite(parent, websocket);
                }
            });
        }
        template<class PARENTTYPE>void closeImpl(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, unsigned short code, const std::string& msg) {
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "closeImpl " << msg);
            WSMessage ws;
            ws.code = OpCode::CLOSE;
            ws.len = sizeof(code) + msg.size();
            ws.Buffer = std::shared_ptr<unsigned char>(new unsigned char[ws.len], [](unsigned char* p) { delete[] p; });
            *reinterpret_cast<unsigned short*>(ws.Buffer.get()) = ntoh(code);
            memcpy(ws.Buffer.get() + sizeof(code), msg.c_str(), msg.size());
            ws.data = ws.Buffer.get();
            sendImpl(parent, websocket, ws, false);
        }


        template<class PARENTYPE, class SOCKETTYPE, class SENDBUFFERTYPE>inline void handleclose(const PARENTYPE& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Closed: " << msg.code);
            if (parent->onDisconnection) {
                WSocket ws(websocket);
                parent->onDisconnection(ws, msg.code, "");

            }
            websocket->canceltimers();
            std::error_code ec;
            socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            ec.clear();
            socket->lowest_layer().close(ec);
        }
        template<class PARENTYPE, class SOCKETTYPE, class SENDBUFFERTYPE>inline void write_end(const PARENTYPE& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {

            asio::async_write(*socket, asio::buffer(msg.data, msg.len), websocket->strand.wrap([parent, websocket, socket, msg](const std::error_code& ec, size_t bytes_transferred) {
                if (!websocket->SendMessageQueue.empty()) {
                    websocket->SendMessageQueue.pop_front();
                }
                UNUSED(bytes_transferred);
                //   assert(msg.len == bytes_transferred);
                if (ec)
                {
                    return closeImpl(parent, websocket, 1002, "write header failed " + ec.message());
                }

                if (msg.code == OpCode::CLOSE) {
                    handleclose(parent, websocket, socket, msg);
                }
                else {
                    startwrite(parent, websocket);
                }
            }));
        }

        template<class SOCKETTYPE, class SENDBUFFERTYPE>inline void writeend(const std::shared_ptr<WSClientImpl>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {
            std::uniform_int_distribution<unsigned int> dist(0, 255);
            std::random_device rd;

            unsigned char mask[4];
            for (auto c = 0; c < 4; c++) {
                mask[c] = static_cast<unsigned char>(dist(rd));
            }
            auto p = reinterpret_cast<unsigned char*>(msg.data);
            for (decltype(msg.len) i = 0; i < msg.len; i++) {
                *p++ ^= mask[i % 4];
            }
            std::error_code ec;
            auto bytes_transferred = asio::write(*socket, asio::buffer(mask, 4), ec);
            UNUSED(bytes_transferred);
            assert(bytes_transferred == 4);
            if (ec)
            {
                if (msg.code == OpCode::CLOSE) {
                    handleclose(parent, websocket, socket, msg);
                }
                else {
                    return closeImpl(parent, websocket, 1002, "write mask failed " + ec.message());
                }
            }
            else {
                write_end(parent, websocket, socket, msg);
            }
        }
        template<class SOCKETTYPE, class SENDBUFFERTYPE>inline void writeend(const std::shared_ptr<WSListenerImpl>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {
            write_end(parent, websocket, socket, msg);
        }

        template<class PARENTTYPE, class SOCKETTYPE, class SENDBUFFERTYPE>inline void write(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {
            size_t sendsize = 0;
            unsigned char header[10] = {};

            setFin(header, 0xFF);
            set_MaskBitForSending<PARENTTYPE>(header);
            setOpCode(header, msg.code);
            setrsv1(header, 0x00);
            setrsv2(header, 0x00);
            setrsv3(header, 0x00);


            if (msg.len <= 125) {
                setpayloadLength1(header, hton(static_cast<unsigned char>(msg.len)));
                sendsize = 2;
            }
            else if (msg.len > USHRT_MAX) {
                setpayloadLength8(header, hton(static_cast<unsigned long long int>(msg.len)));
                setpayloadLength1(header, 127);
                sendsize = 10;
            }
            else {
                setpayloadLength2(header, hton(static_cast<unsigned short>(msg.len)));
                setpayloadLength1(header, 126);
                sendsize = 4;
            }

            assert(msg.len < UINT32_MAX);
            writeexpire_from_now(parent, websocket, socket, parent->WriteTimeout);
            std::error_code ec;
            auto bytes_transferred = asio::write(*socket, asio::buffer(header, sendsize), ec);
            UNUSED(bytes_transferred);
            if (!ec)
            {
                assert(sendsize == bytes_transferred);
                writeend(parent, websocket, socket, msg);
            }
            else {
                return closeImpl(parent, websocket, 1002, "write header failed   " + ec.message());
            }

        }
        inline void UnMaskMessage(const std::shared_ptr<WSListenerImpl>& parent, size_t readsize, unsigned char* buffer) {
            UNUSED(parent);
            auto startp = buffer;
            unsigned char mask[4];
            memcpy(mask, startp, 4);
            for (size_t c = 4; c < readsize; c++) {
                startp[c - 4] = startp[c] ^ mask[c % 4];
            }
        }
        inline void UnMaskMessage(const std::shared_ptr<WSClientImpl>& parent, size_t readsize, unsigned char* buffer) {
            UNUSED(parent);
            UNUSED(readsize);
            UNUSED(buffer);
        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ProcessMessage(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket) {

            auto opcode = getOpCode(websocket->ReceiveHeader);

            if (!getFin(websocket->ReceiveHeader)) {
                if (websocket->LastOpCode == OpCode::INVALID) {
                    if (opcode != OpCode::BINARY && opcode != OpCode::TEXT) {
                        return closeImpl(parent, websocket, 1002, "First Non Fin Frame must be binary or text");
                    }
                    websocket->LastOpCode = opcode;
                }
                else if (opcode != OpCode::CONTINUATION) {
                    return closeImpl(parent, websocket, 1002, "Continuation Received without a previous frame");
                }
                ReadHeaderNext(parent, websocket, socket);
            }
            else {

                if (websocket->LastOpCode != OpCode::INVALID && opcode != OpCode::CONTINUATION) {
                    return closeImpl(parent, websocket, 1002, "Continuation Received without a previous frame");
                }
                else if (websocket->LastOpCode == OpCode::INVALID && opcode == OpCode::CONTINUATION) {
                    return closeImpl(parent, websocket, 1002, "Continuation Received without a previous frame");
                }
                else if (websocket->LastOpCode == OpCode::TEXT || opcode == OpCode::TEXT) {
                    if (!isValidUtf8(websocket->ReceiveBuffer, websocket->ReceiveBufferSize)) {
                        return closeImpl(parent, websocket, 1007, "Frame not valid utf8");
                    }
                }
                if (parent->onMessage) {
                    WSocket wsocket(websocket);

                    auto unpacked = WSMessage{ websocket->ReceiveBuffer,   websocket->ReceiveBufferSize, websocket->LastOpCode != OpCode::INVALID ? websocket->LastOpCode : opcode };
                    parent->onMessage(wsocket, unpacked);
                }
                ReadHeaderStart(parent, websocket, socket);
            }
        }
        template <class PARENTTYPE>inline void SendPong(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const std::shared_ptr<unsigned char>& buffer, size_t size) {
            WSMessage msg;
            msg.Buffer = buffer;
            msg.len = size;
            msg.code = OpCode::PONG;
            msg.data = msg.Buffer.get();

            sendImpl(parent, websocket, msg, false);
        }
        template <class PARENTTYPE>inline void ProcessClose(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const std::shared_ptr<unsigned char>& buffer, size_t size) {
            if (size >= 2) {
                auto closecode = hton(*reinterpret_cast<unsigned short*>(buffer.get()));
                if (size > 2) {
                    if (!isValidUtf8(buffer.get() + sizeof(closecode), size - sizeof(closecode))) {
                        return closeImpl(parent, websocket, 1007, "Frame not valid utf8");
                    }
                }

                if (((closecode >= 1000 && closecode <= 1011) || (closecode >= 3000 && closecode <= 4999)) && closecode != 1004 && closecode != 1005 && closecode != 1006) {
                    return closeImpl(parent, websocket, 1000, "");
                }
                else
                {
                    return closeImpl(parent, websocket, 1002, "");
                }
            }
            else if (size != 0) {
                return closeImpl(parent, websocket, 1002, "");
            }
            return closeImpl(parent, websocket, 1000, "");
        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ProcessControlMessage(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const std::shared_ptr<unsigned char>& buffer, size_t size) {
            if (!getFin(websocket->ReceiveHeader)) {
                return closeImpl(parent, websocket, 1002, "Closing connection. Control Frames must be Fin");
            }
            auto opcode = getOpCode(websocket->ReceiveHeader);

            WSocket wsocket(websocket);
            switch (opcode)
            {
            case OpCode::PING:
                if (parent->onPing) {
                    parent->onPing(wsocket, buffer.get(), size);
                }
                SendPong(parent, websocket, buffer, size);
                break;
            case OpCode::PONG:
                if (parent->onPong) {
                    parent->onPong(wsocket, buffer.get(), size);
                }
                // SendPong(parent, websocket);
                break;
            case OpCode::CLOSE:
                return ProcessClose(parent, websocket, buffer, size);

            default:
                return closeImpl(parent, websocket, 1002, "Closing connection. nonvalid op code");
            }
            ReadHeaderNext(parent, websocket, socket);

        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadBody(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket) {

            if (!DidPassMaskRequirement<PARENTTYPE>(websocket->ReceiveHeader)) {//Close connection if it did not meet the mask requirement. 
                return closeImpl(parent, websocket, 1002, "Closing connection because mask requirement not met");
            }

            if (getrsv2(websocket->ReceiveHeader) || getrsv3(websocket->ReceiveHeader) || (getrsv1(websocket->ReceiveHeader) && !websocket->CompressionEnabled)) {
                return closeImpl(parent, websocket, 1002, "Closing connection. rsv bit set");
            }

            auto opcode = getOpCode(websocket->ReceiveHeader);

            size_t size = getpayloadLength1(websocket->ReceiveHeader);
            switch (size) {
            case 126:
                size = ntoh(getpayloadLength2(websocket->ReceiveHeader));
                break;
            case 127:
                size = static_cast<size_t>(ntoh(getpayloadLength8(websocket->ReceiveHeader)));
                if (size > std::numeric_limits<std::size_t>::max()) {
                    return closeImpl(parent, websocket, 1009, "Payload exceeded MaxPayload size");
                }
                break;
            default:
                break;
            }

            size += AdditionalBodyBytesToRead<PARENTTYPE>();
            if (opcode == OpCode::PING || opcode == OpCode::PONG || opcode == OpCode::CLOSE) {
                if (size - AdditionalBodyBytesToRead<PARENTTYPE>() > CONTROLBUFFERMAXSIZE) {
                    return closeImpl(parent, websocket, 1002, "Payload exceeded for control frames. Size requested " + std::to_string(size));
                }
                else if (size > 0) {
                    auto buffer = std::shared_ptr<unsigned char>(new unsigned char[size], [](auto p) { delete[] p; });
                    asio::async_read(*socket, asio::buffer(buffer.get(), size), [parent, websocket, socket, buffer, size](const std::error_code& ec, size_t bytes_transferred) {

                        if (!ec) {
                            assert(size == bytes_transferred);
                            if (size != bytes_transferred) {
                                return closeImpl(parent, websocket, 1002, "Did not receive all bytes ... ");
                            }
                            UnMaskMessage(parent, size, buffer.get());

                            auto tempsize = size - AdditionalBodyBytesToRead<PARENTTYPE>();
                            ProcessControlMessage(parent, websocket, socket, buffer, tempsize);
                        }
                        else {
                            return closeImpl(parent, websocket, 1002, "ReadBody Error " + ec.message());
                        }
                    });
                }
                else {
                    std::shared_ptr<unsigned char> ptr;
                    ProcessControlMessage(parent, websocket, socket, ptr, 0);
                }
            }

            else if (opcode == OpCode::TEXT || opcode == OpCode::BINARY || opcode == OpCode::CONTINUATION) {
                auto addedsize = websocket->ReceiveBufferSize + size;
                if (addedsize > std::numeric_limits<std::size_t>::max()) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "payload exceeds memory on system!!! ");
                    return closeImpl(parent, websocket, 1009, "Payload exceeded MaxPayload size");
                }
                websocket->ReceiveBufferSize = addedsize;

                if (websocket->ReceiveBufferSize > parent->MaxPayload) {
                    return closeImpl(parent, websocket, 1009, "Payload exceeded MaxPayload size");
                }
                if (websocket->ReceiveBufferSize > std::numeric_limits<std::size_t>::max()) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "payload exceeds memory on system!!! ");
                    return closeImpl(parent, websocket, 1009, "Payload exceeded MaxPayload size");
                }

                if (size > 0) {
                    websocket->ReceiveBuffer = static_cast<unsigned char*>(realloc(websocket->ReceiveBuffer, websocket->ReceiveBufferSize));
                    if (!websocket->ReceiveBuffer) {
                        SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "MEMORY ALLOCATION ERROR!!!");
                        return closeImpl(parent, websocket, 1009, "Payload exceeded MaxPayload size");
                    }
                    asio::async_read(*socket, asio::buffer(websocket->ReceiveBuffer + websocket->ReceiveBufferSize - size, size), [parent, websocket, socket, size](const std::error_code& ec, size_t bytes_transferred) {

                        if (!ec) {
                            assert(size == bytes_transferred);
                            if (size != bytes_transferred) {
                                return closeImpl(parent, websocket, 1002, "Did not receive all bytes ... ");
                            }
                            auto buffer = websocket->ReceiveBuffer + websocket->ReceiveBufferSize - size;
                            UnMaskMessage(parent, size, buffer);
                            websocket->ReceiveBufferSize -= AdditionalBodyBytesToRead<PARENTTYPE>();
                            ProcessMessage(parent, websocket, socket);
                        }
                        else {
                            return closeImpl(parent, websocket, 1002, "ReadBody Error " + ec.message());
                        }
                    });
                }
                else {
                    ProcessMessage(parent, websocket, socket);
                }
            }
            else {
                return closeImpl(parent, websocket, 1002, "Closing connection. nonvalid op code");
            }

        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadHeaderStart(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket) {
            free(websocket->ReceiveBuffer);
            websocket->ReceiveBuffer = nullptr;
            websocket->ReceiveBufferSize = 0;
            websocket->LastOpCode = OpCode::INVALID;
            ReadHeaderNext(parent, websocket, socket);
        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadHeaderNext(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket) {
            readexpire_from_now(parent, websocket, socket, parent->ReadTimeout);
            asio::async_read(*socket, asio::buffer(websocket->ReceiveHeader, 2), [parent, websocket, socket](const std::error_code& ec, size_t bytes_transferred) {
                UNUSED(bytes_transferred);
                if (!ec) {
                  //  assert(bytes_transferred == 2);

                    size_t readbytes = getpayloadLength1(websocket->ReceiveHeader);
                    switch (readbytes) {
                    case 126:
                        readbytes = 2;
                        break;
                    case 127:
                        readbytes = 8;
                        break;
                    default:
                        readbytes = 0;
                    }


                    if (readbytes > 1) {
                        asio::async_read(*socket, asio::buffer(websocket->ReceiveHeader + 2, readbytes), [parent, websocket, socket](const std::error_code& ec, size_t) {
                            if (!ec) {
                                ReadBody(parent, websocket, socket);
                            }
                            else {
                                return closeImpl(parent, websocket, 1002, "readheader ExtendedPayloadlen " + ec.message());
                            }
                        });
                    }
                    else {
                        ReadBody(parent, websocket, socket);
                    }

                }
                else {
                    return closeImpl(parent, websocket, 1002, "WebSocket ReadHeader failed " + ec.message());
                }
            });
        }
    }
}