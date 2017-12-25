#pragma once
#include "SocketIOStatus.h"
#include "Utils.h"
#include "asio/streambuf.hpp"
#include <deque>
#include <memory>
#include <random>
#include <string>
namespace SL {
namespace WS_LITE {
    // forward declares
    struct ThreadContext;
    template <bool isServer, class SOCKETTYPE> void ReadHeaderNext(const SOCKETTYPE &socket, const std::shared_ptr<asio::streambuf> &extradata);
    template <bool isServer, class SOCKETTYPE> void ReadHeaderStart(const SOCKETTYPE &socket, const std::shared_ptr<asio::streambuf> &extradata);
    template <bool isServer, class SOCKETTYPE, class SENDBUFFERTYPE> void write_end(const SOCKETTYPE &socket, const SENDBUFFERTYPE &msg);
    template <bool isServer, class SOCKETTYPE, class SENDBUFFERTYPE>
    void sendImpl(const SOCKETTYPE &socket, const SENDBUFFERTYPE &msg, CompressionOptions compressmessage);
    template <bool isServer, class SOCKETTYPE> void sendclosemessage(const SOCKETTYPE &socket, unsigned short code, const std::string &msg);

    inline size_t ReadFromExtraData(unsigned char *dst, size_t desired_bytes_to_read, const std::shared_ptr<asio::streambuf> &extradata)
    {
        size_t dataconsumed = 0;
        if (extradata->size() >= desired_bytes_to_read) {
            dataconsumed = desired_bytes_to_read;
        }
        else {
            dataconsumed = extradata->size();
        }
        if (dataconsumed > 0) {
            desired_bytes_to_read -= dataconsumed;
            memcpy(dst, asio::buffer_cast<const void *>(extradata->data()), dataconsumed);
            extradata->consume(dataconsumed);
        }
        return dataconsumed;
    }
    template <bool isServer, class SOCKETTYPE> void readexpire_from_now(const SOCKETTYPE &socket, std::chrono::seconds secs)
    {
        std::error_code ec;
        if (secs.count() == 0)
            socket->read_deadline.cancel(ec);
        socket->read_deadline.expires_from_now(secs, ec);
        if (ec) {
            SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
        }
        else if (secs.count() > 0) {
            socket->read_deadline.async_wait([socket](const std::error_code &ec) {
                if (ec != asio::error::operation_aborted) {
                    return sendclosemessage<isServer>(socket, 1001, "read timer expired on the socket ");
                }
            });
        }
    }
    template <bool isServer, class SOCKETTYPE> void start_ping(const SOCKETTYPE &socket, std::chrono::seconds secs)
    {
        std::error_code ec;
        if (secs.count() == 0)
            socket->ping_deadline.cancel(ec);
        socket->ping_deadline.expires_from_now(secs, ec);
        if (ec) {
            SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
        }
        else if (secs.count() > 0) {
            socket->ping_deadline.async_wait([socket, secs](const std::error_code &ec) {
                if (ec != asio::error::operation_aborted) {
                    WSMessage msg;
                    char p[] = "ping";
                    msg.Buffer = std::shared_ptr<unsigned char>(new unsigned char[sizeof(p)], [](unsigned char *ptr) { delete[] ptr; });
                    memcpy(msg.Buffer.get(), p, sizeof(p));
                    msg.len = sizeof(p);
                    msg.code = OpCode::PING;
                    msg.data = msg.Buffer.get();
                    SL::WS_LITE::sendImpl<isServer>(socket, msg, CompressionOptions::NO_COMPRESSION);
                    start_ping<isServer>(socket, secs);
                }
            });
        }
    }
    template <bool isServer, class SOCKETTYPE> void writeexpire_from_now(const SOCKETTYPE &socket, std::chrono::seconds secs)
    {

        std::error_code ec;
        if (secs.count() == 0)
            socket->write_deadline.cancel(ec);
        socket->write_deadline.expires_from_now(secs, ec);
        if (ec) {
            SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
        }
        else if (secs.count() > 0) {
            socket->write_deadline.async_wait([socket](const std::error_code &ec) {
                if (ec != asio::error::operation_aborted) {
                    return sendclosemessage<isServer>(socket, 1001, "write timer expired on the socket ");
                }
            });
        }
    }

    template <bool isServer, class SOCKETTYPE, class SENDBUFFERTYPE> void writeend(const SOCKETTYPE &socket, const SENDBUFFERTYPE &msg, bool iserver)
    {
        if (!iserver) {
            std::uniform_int_distribution<unsigned int> dist(0, 255);
            std::random_device rd;

            unsigned char mask[4];
            for (auto c = 0; c < 4; c++) {
                mask[c] = static_cast<unsigned char>(dist(rd));
            }
            auto p = reinterpret_cast<unsigned char *>(msg.data);
            for (decltype(msg.len) i = 0; i < msg.len; i++) {
                *p++ ^= mask[i % 4];
            }
            std::error_code ec;
            auto bytes_transferred = asio::write(socket->Socket, asio::buffer(mask, 4), ec);
            if (ec) {
                if (msg.code == OpCode::CLOSE) {
                    return handleclose(socket, msg.code, "");
                }
                else {
                    return handleclose(socket, 1002, "write mask failed " + ec.message());
                }
            }
            else {
                UNUSED(bytes_transferred);
                assert(bytes_transferred == 4);
                write_end<isServer>(socket, msg);
            }
        }
        else {
            write_end<isServer>(socket, msg);
        }
    }
    template <bool isServer, class SOCKETTYPE, class SENDBUFFERTYPE> inline void write(const SOCKETTYPE &socket, const SENDBUFFERTYPE &msg)
    {
        size_t sendsize = 0;
        unsigned char header[10] = {};

        setFin(header, 0xFF);
        set_MaskBitForSending(header, isServer);
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
        writeexpire_from_now<isServer>(socket, socket->Parent->WriteTimeout);
        std::error_code ec;
        auto bytes_transferred = asio::write(socket->Socket, asio::buffer(header, sendsize), ec);
        UNUSED(bytes_transferred);
        if (!ec) {
            assert(sendsize == bytes_transferred);
            writeend<isServer>(socket, msg, isServer);
        }
        else {
            handleclose(socket, 1002, "write header failed " + ec.message());
        }
    }
    template <bool isServer, class SOCKETTYPE> inline void startwrite(const SOCKETTYPE &socket)
    {
        if (socket->Writing == SocketIOStatus::NOTWRITING) {
            if (!socket->SendMessageQueue.empty()) {
                socket->Writing = SocketIOStatus::WRITING;
                auto msg(socket->SendMessageQueue.front());
                socket->SendMessageQueue.pop_front();
                write<isServer>(socket, msg.msg);
            }
            else {
                writeexpire_from_now<isServer>(socket, std::chrono::seconds(0)); // make sure the write timer doesnt kick off
            }
        }
    }
    template <bool isServer, class SOCKETTYPE, class SENDBUFFERTYPE>
    void sendImpl(const SOCKETTYPE &socket, const SENDBUFFERTYPE &msg, CompressionOptions compressmessage)
    {
        if (compressmessage == CompressionOptions::COMPRESS) {
            assert(msg.code == OpCode::BINARY || msg.code == OpCode::TEXT);
        }

        socket->Socket.get_io_service().post([socket, msg, compressmessage]() {

            if (socket->SocketStatus_ == SocketStatus::CONNECTED) {
                // update the socket status to reflect it is closing to prevent other messages from being sent.. this is the last valid message
                // make sure to do this after a call to write so the write process sends the close message, but no others
                if (msg.code == OpCode::CLOSE) {
                    socket->SocketStatus_ = SocketStatus::CLOSING;
                }
                socket->Bytes_PendingFlush += msg.len;
                socket->SendMessageQueue.emplace_back(msg, compressmessage);
                SL::WS_LITE::startwrite<isServer>(socket);
            }
        });
    }
    template <bool isServer, class SOCKETTYPE> void sendclosemessage(const SOCKETTYPE &socket, unsigned short code, const std::string &msg)
    {
        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "closeImpl " << msg);
        WSMessage ws;
        ws.code = OpCode::CLOSE;
        ws.len = sizeof(code) + msg.size();
        ws.Buffer = std::shared_ptr<unsigned char>(new unsigned char[ws.len], [](unsigned char *p) { delete[] p; });
        *reinterpret_cast<unsigned short *>(ws.Buffer.get()) = ntoh(code);
        memcpy(ws.Buffer.get() + sizeof(code), msg.c_str(), msg.size());
        ws.data = ws.Buffer.get();
        sendImpl<isServer>(socket, ws, CompressionOptions::NO_COMPRESSION);
    }

    template <class SOCKETTYPE> inline void handleclose(const SOCKETTYPE &socket, unsigned short code, const std::string &msg)
    {
        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Closed: " << code);
        socket->SocketStatus_ = SocketStatus::CLOSED;
        socket->Writing = SocketIOStatus::NOTWRITING;
        if (socket->Parent->onDisconnection) {
            socket->Parent->onDisconnection(socket, code, msg);
        }

        socket->SendMessageQueue.clear(); // clear all outbound messages
        socket->canceltimers();
        std::error_code ec;
        socket->Socket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        ec.clear();
        socket->Socket.lowest_layer().close(ec);
    }

    template <bool isServer, class SOCKETTYPE, class SENDBUFFERTYPE> void write_end(const SOCKETTYPE &socket, const SENDBUFFERTYPE &msg)
    {

        asio::async_write(socket->Socket, asio::buffer(msg.data, msg.len), [socket, msg](const std::error_code &ec, size_t bytes_transferred) {
            socket->Writing = SocketIOStatus::NOTWRITING;
            UNUSED(bytes_transferred);
            socket->Bytes_PendingFlush -= msg.len;
            if (msg.code == OpCode::CLOSE) {
                // final close.. get out and dont come back mm kay?
                return handleclose(socket, 1000, "");
            }
            if (ec) {
                return handleclose(socket, 1002, "write header failed " + ec.message());
            }
            assert(msg.len == bytes_transferred);
            startwrite<isServer>(socket);
        });
    }

    inline void UnMaskMessage(size_t readsize, unsigned char *buffer, bool isserver)
    {
        if (isserver) {
            auto startp = buffer;
            unsigned char mask[4] = {};
            memcpy(mask, startp, 4);
            for (size_t c = 4; c < readsize; c++) {
                startp[c - 4] = startp[c] ^ mask[c % 4];
            }
        }
    }

    template <bool isServer, class SOCKETTYPE> inline void ProcessMessage(const SOCKETTYPE &socket, const std::shared_ptr<asio::streambuf> &extradata)
    {

        auto opcode = static_cast<OpCode>(getOpCode(socket->ReceiveHeader));

        if (!getFin(socket->ReceiveHeader)) {
            if (socket->LastOpCode == OpCode::INVALID) {
                if (opcode != OpCode::BINARY && opcode != OpCode::TEXT) {
                    return sendclosemessage<isServer>(socket, 1002, "First Non Fin Frame must be binary or text");
                }
                socket->LastOpCode = opcode;
            }
            else if (opcode != OpCode::CONTINUATION) {
                return sendclosemessage<isServer>(socket, 1002, "Continuation Received without a previous frame");
            }
            return ReadHeaderNext<isServer>(socket, extradata);
        }
        else {

            if (socket->LastOpCode != OpCode::INVALID && opcode != OpCode::CONTINUATION) {
                return sendclosemessage<isServer>(socket, 1002, "Continuation Received without a previous frame");
            }
            else if (socket->LastOpCode == OpCode::INVALID && opcode == OpCode::CONTINUATION) {
                return sendclosemessage<isServer>(socket, 1002, "Continuation Received without a previous frame");
            }
            else if (socket->LastOpCode == OpCode::TEXT || opcode == OpCode::TEXT) {
                if (!isValidUtf8(socket->ReceiveBuffer, socket->ReceiveBufferSize)) {
                    return sendclosemessage<isServer>(socket, 1007, "Frame not valid utf8");
                }
            }
            if (socket->Parent->onMessage) {
                if (getrsv1(socket->ReceiveHeader) && socket->ExtensionOption == ExtensionOptions::DEFLATE) {
                }

                auto unpacked =
                    WSMessage{socket->ReceiveBuffer, socket->ReceiveBufferSize, socket->LastOpCode != OpCode::INVALID ? socket->LastOpCode : opcode};
                socket->Parent->onMessage(socket, unpacked);
            }
        }
        ReadHeaderStart<isServer>(socket, extradata);
    }

    template <bool isServer, class SOCKETTYPE>
    inline void SendPong(const SOCKETTYPE &socket, const std::shared_ptr<unsigned char> &buffer, size_t size)
    {
        WSMessage msg;
        msg.Buffer = buffer;
        msg.len = size;
        msg.code = OpCode::PONG;
        msg.data = msg.Buffer.get();

        sendImpl<isServer>(socket, msg, CompressionOptions::NO_COMPRESSION);
    }
    template <bool isServer, class SOCKETTYPE>
    inline void ProcessClose(const SOCKETTYPE &socket, const std::shared_ptr<unsigned char> &buffer, size_t size)
    {
        if (size >= 2) {
            auto closecode = hton(*reinterpret_cast<unsigned short *>(buffer.get()));
            if (size > 2) {
                if (!isValidUtf8(buffer.get() + sizeof(closecode), size - sizeof(closecode))) {
                    return sendclosemessage<isServer>(socket, 1007, "Frame not valid utf8");
                }
            }

            if (((closecode >= 1000 && closecode <= 1011) || (closecode >= 3000 && closecode <= 4999)) && closecode != 1004 && closecode != 1005 &&
                closecode != 1006) {
                return sendclosemessage<isServer>(socket, 1000, "");
            }
            else {
                return sendclosemessage<isServer>(socket, 1002, "");
            }
        }
        else if (size != 0) {
            return sendclosemessage<isServer>(socket, 1002, "");
        }
        return sendclosemessage<isServer>(socket, 1000, "");
    }
    template <bool isServer, class SOCKETTYPE>
    inline void ProcessControlMessage(const SOCKETTYPE &socket, const std::shared_ptr<unsigned char> &buffer, size_t size,
                                      const std::shared_ptr<asio::streambuf> &extradata)
    {
        if (!getFin(socket->ReceiveHeader)) {
            return sendclosemessage<isServer>(socket, 1002, "Closing connection. Control Frames must be Fin");
        }
        auto opcode = static_cast<OpCode>(getOpCode(socket->ReceiveHeader));

        switch (opcode) {
        case OpCode::PING:
            if (socket->Parent->onPing) {
                socket->Parent->onPing(socket, buffer.get(), size);
            }
            SendPong<isServer>(socket, buffer, size);
            break;
        case OpCode::PONG:
            if (socket->Parent->onPong) {
                socket->Parent->onPong(socket, buffer.get(), size);
            }
            break;
        case OpCode::CLOSE:
            return ProcessClose<isServer>(socket, buffer, size);

        default:
            return sendclosemessage<isServer>(socket, 1002, "Closing connection. nonvalid op code");
        }
        ReadHeaderNext<isServer>(socket, extradata);
    }

    template <bool isServer, class SOCKETTYPE> inline void ReadBody(const SOCKETTYPE &socket, const std::shared_ptr<asio::streambuf> &extradata)
    {
        if (!DidPassMaskRequirement(socket->ReceiveHeader, isServer)) { // Close connection if it did not meet the mask requirement.
            return sendclosemessage<isServer>(socket, 1002, "Closing connection because mask requirement not met");
        }
        if (getrsv2(socket->ReceiveHeader) || getrsv3(socket->ReceiveHeader) ||
            (getrsv1(socket->ReceiveHeader) && socket->ExtensionOption == ExtensionOptions::NO_OPTIONS)) {
            return sendclosemessage<isServer>(socket, 1002, "Closing connection. rsv bit set");
        }
        auto opcode = static_cast<OpCode>(getOpCode(socket->ReceiveHeader));

        size_t size = getpayloadLength1(socket->ReceiveHeader);
        switch (size) {
        case 126:
            size = ntoh(getpayloadLength2(socket->ReceiveHeader));
            break;
        case 127:
            size = static_cast<size_t>(ntoh(getpayloadLength8(socket->ReceiveHeader)));
            if (size > std::numeric_limits<std::size_t>::max()) {
                return sendclosemessage<isServer>(socket, 1009, "Payload exceeded MaxPayload size");
            }
            break;
        default:
            break;
        }

        size += AdditionalBodyBytesToRead(isServer);
        if (opcode == OpCode::PING || opcode == OpCode::PONG || opcode == OpCode::CLOSE) {
            if (size - AdditionalBodyBytesToRead(isServer) > CONTROLBUFFERMAXSIZE) {
                return sendclosemessage<isServer>(socket, 1002, "Payload exceeded for control frames. Size requested " + std::to_string(size));
            }
            else if (size > 0) {
                auto buffer = std::shared_ptr<unsigned char>(new unsigned char[size], [](unsigned char *p) { delete[] p; });

                auto bytestoread = size;
                auto dataconsumed = ReadFromExtraData(buffer.get(), bytestoread, extradata);
                bytestoread -= dataconsumed;

                asio::async_read(socket->Socket, asio::buffer(buffer.get() + dataconsumed, bytestoread),
                                 [size, extradata, socket, buffer](const std::error_code &ec, size_t) {
                                     if (!ec) {
                                         UnMaskMessage(size, buffer.get(), isServer);
                                         auto tempsize = size - AdditionalBodyBytesToRead(isServer);
                                         return ProcessControlMessage<isServer>(socket, buffer, tempsize, extradata);
                                     }
                                     else {
                                         return sendclosemessage<isServer>(socket, 1002, "ReadBody Error " + ec.message());
                                     }
                                 });
            }
            else {
                std::shared_ptr<unsigned char> ptr;
                return ProcessControlMessage<isServer>(socket, ptr, 0, extradata);
            }
        }

        else if (opcode == OpCode::TEXT || opcode == OpCode::BINARY || opcode == OpCode::CONTINUATION) {
            auto addedsize = socket->ReceiveBufferSize + size;
            if (addedsize > std::numeric_limits<std::size_t>::max()) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "payload exceeds memory on system!!! ");
                return sendclosemessage<isServer>(socket, 1009, "Payload exceeded MaxPayload size");
            }
            socket->ReceiveBufferSize = addedsize;

            if (socket->ReceiveBufferSize > socket->Parent->MaxPayload) {
                return sendclosemessage<isServer>(socket, 1009, "Payload exceeded MaxPayload size");
            }
            if (socket->ReceiveBufferSize > std::numeric_limits<std::size_t>::max()) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "payload exceeds memory on system!!! ");
                return sendclosemessage<isServer>(socket, 1009, "Payload exceeded MaxPayload size");
            }

            if (size > 0) {
                socket->ReceiveBuffer = static_cast<unsigned char *>(realloc(socket->ReceiveBuffer, socket->ReceiveBufferSize));
                if (!socket->ReceiveBuffer) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "MEMORY ALLOCATION ERROR!!! Tried to realloc " << socket->ReceiveBufferSize);
                    return sendclosemessage<isServer>(socket, 1009, "Payload exceeded MaxPayload size");
                }

                auto bytestoread = size;
                auto dataconsumed = ReadFromExtraData(socket->ReceiveBuffer + socket->ReceiveBufferSize - size, bytestoread, extradata);
                bytestoread -= dataconsumed;

                asio::async_read(socket->Socket, asio::buffer(socket->ReceiveBuffer + socket->ReceiveBufferSize - size + dataconsumed, bytestoread),
                                 [size, extradata, socket](const std::error_code &ec, size_t) {
                                     if (!ec) {
                                         auto buffer = socket->ReceiveBuffer + socket->ReceiveBufferSize - size;
                                         UnMaskMessage(size, buffer, isServer);
                                         socket->ReceiveBufferSize -= AdditionalBodyBytesToRead(isServer);
                                         return ProcessMessage<isServer>(socket, extradata);
                                     }
                                     else {
                                         return sendclosemessage<isServer>(socket, 1002, "ReadBody Error " + ec.message());
                                     }
                                 });
            }
            else {
                return ProcessMessage<isServer>(socket, extradata);
            }
        }
        else {
            return sendclosemessage<isServer>(socket, 1002, "Closing connection. nonvalid op code");
        }
    }

    template <bool isServer, class SOCKETTYPE> void ReadHeaderNext(const SOCKETTYPE &socket, const std::shared_ptr<asio::streambuf> &extradata)
    {
        readexpire_from_now<isServer>(socket, socket->Parent->ReadTimeout);
        size_t bytestoread = 2;
        auto dataconsumed = ReadFromExtraData(socket->ReceiveHeader, bytestoread, extradata);
        bytestoread -= dataconsumed;

        asio::async_read(
            socket->Socket, asio::buffer(socket->ReceiveHeader + dataconsumed, bytestoread), [socket, extradata](const std::error_code &ec, size_t) {
                if (!ec) {
                    size_t bytestoread = getpayloadLength1(socket->ReceiveHeader);
                    switch (bytestoread) {
                    case 126:
                        bytestoread = 2;
                        break;
                    case 127:
                        bytestoread = 8;
                        break;
                    default:
                        bytestoread = 0;
                    }
                    if (bytestoread > 1) {
                        auto dataconsumed = ReadFromExtraData(socket->ReceiveHeader + 2, bytestoread, extradata);
                        bytestoread -= dataconsumed;

                        asio::async_read(socket->Socket, asio::buffer(socket->ReceiveHeader + 2 + dataconsumed, bytestoread),
                                         [socket, extradata](const std::error_code &ec, size_t) {
                                             if (!ec) {
                                                 ReadBody<isServer>(socket, extradata);
                                             }
                                             else {
                                                 return sendclosemessage<isServer>(socket, 1002, "readheader ExtendedPayloadlen " + ec.message());
                                             }
                                         });
                    }
                    else {
                        ReadBody<isServer>(socket, extradata);
                    }
                }
                else {
                    return sendclosemessage<isServer>(socket, 1002, "WebSocket ReadHeader failed " + ec.message());
                }
            });
    }
    template <bool isServer, class SOCKETTYPE> void ReadHeaderStart(const SOCKETTYPE &socket, const std::shared_ptr<asio::streambuf> &extradata)
    {
        free(socket->ReceiveBuffer);
        socket->ReceiveBuffer = nullptr;
        socket->ReceiveBufferSize = 0;
        socket->LastOpCode = OpCode::INVALID;
        ReadHeaderNext<isServer>(socket, extradata);
    }

    class WSClient final : public IWSHub {
        std::shared_ptr<WSContext> Impl_;

      public:
        WSClient(const std::shared_ptr<WSContext> &c) : Impl_(c) {}
        virtual ~WSClient() {}
        virtual void set_MaxPayload(size_t bytes) override;
        virtual size_t get_MaxPayload() override;
        virtual void set_ReadTimeout(std::chrono::seconds seconds) override;
        virtual std::chrono::seconds get_ReadTimeout() override;
        virtual void set_WriteTimeout(std::chrono::seconds seconds) override;
        virtual std::chrono::seconds get_WriteTimeout() override;
    };
    class WSListener final : public IWSHub {
        std::shared_ptr<WSContext> Impl_;

      public:
        WSListener(const std::shared_ptr<WSContext> &impl) : Impl_(impl) {}
        virtual ~WSListener() {}
        void set_MaxPayload(size_t bytes) override;
        virtual size_t get_MaxPayload() override;
        virtual void set_ReadTimeout(std::chrono::seconds seconds) override;
        virtual std::chrono::seconds get_ReadTimeout() override;
        virtual void set_WriteTimeout(std::chrono::seconds seconds) override;
        virtual std::chrono::seconds get_WriteTimeout() override;
    };

    class WSListener_Configuration final : public IWSListener_Configuration {
        std::shared_ptr<WSContext> Impl_;

      public:
        virtual ~WSListener_Configuration() {}
        WSListener_Configuration(const std::shared_ptr<WSContext> &impl) : Impl_(impl) {}
        virtual std::shared_ptr<IWSListener_Configuration>
        onConnection(const std::function<void(const std::shared_ptr<IWSocket> &, const HttpHeader &)> &handle) override;
        virtual std::shared_ptr<IWSListener_Configuration>
        onMessage(const std::function<void(const std::shared_ptr<IWSocket> &, const WSMessage &)> &handle) override;
        virtual std::shared_ptr<IWSListener_Configuration>
        onDisconnection(const std::function<void(const std::shared_ptr<IWSocket> &, unsigned short, const std::string &)> &handle) override;
        virtual std::shared_ptr<IWSListener_Configuration>
        onPing(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle) override;
        virtual std::shared_ptr<IWSListener_Configuration>
        onPong(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle) override;
        virtual std::shared_ptr<IWSHub> listen(bool no_delay, bool reuse_address) override;
    };

    class WSClient_Configuration final : public IWSClient_Configuration {
        std::shared_ptr<WSContext> Impl_;

      public:
        WSClient_Configuration(const std::shared_ptr<WSContext> &impl) : Impl_(impl) {}
        virtual ~WSClient_Configuration() {}
        virtual std::shared_ptr<IWSClient_Configuration>
        onConnection(const std::function<void(const std::shared_ptr<IWSocket> &, const HttpHeader &)> &handle) override;
        virtual std::shared_ptr<IWSClient_Configuration>
        onMessage(const std::function<void(const std::shared_ptr<IWSocket> &, const WSMessage &)> &handle) override;
        virtual std::shared_ptr<IWSClient_Configuration>
        onDisconnection(const std::function<void(const std::shared_ptr<IWSocket> &, unsigned short, const std::string &)> &handle) override;
        virtual std::shared_ptr<IWSClient_Configuration>
        onPing(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle) override;
        virtual std::shared_ptr<IWSClient_Configuration>
        onPong(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle) override;

        virtual std::shared_ptr<IWSHub> connect(const std::string &host, PortNumber port, bool no_delay, const std::string &endpoint,
                                                const std::unordered_map<std::string, std::string> &extraheaders) override;
    };
    struct DelayedInfo;
} // namespace WS_LITE
} // namespace SL