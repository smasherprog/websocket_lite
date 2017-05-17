#pragma once
#include "WS_Lite.h"
#include "Utils.h"
#if WIN32
#include <SDKDDKVer.h>
#endif

#include <unordered_map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <memory>
#include <thread>
#include <random>
#include <deque>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

#include <zlib.h>

namespace SL {
    namespace WS_LITE {

        inline char* ZlibInflate(char *data, size_t &length, size_t maxPayload, std::string& dynamicInflationBuffer, z_stream& inflationStream, char* inflationBuffer) {
            dynamicInflationBuffer.clear();

            inflationStream.next_in = (Bytef *)data;
            inflationStream.avail_in = length;

            int err;
            do {
                inflationStream.next_out = (Bytef *)inflationBuffer;
                inflationStream.avail_out = LARGE_BUFFER_SIZE;
                err = ::inflate(&inflationStream, Z_FINISH);
                if (!inflationStream.avail_in) {
                    break;
                }

                dynamicInflationBuffer.append(inflationBuffer, LARGE_BUFFER_SIZE - inflationStream.avail_out);
            } while (err == Z_BUF_ERROR && dynamicInflationBuffer.length() <= maxPayload);

            inflateReset(&inflationStream);

            if ((err != Z_BUF_ERROR && err != Z_OK) || dynamicInflationBuffer.length() > maxPayload) {
                length = 0;
                return nullptr;
            }

            if (dynamicInflationBuffer.length()) {
                dynamicInflationBuffer.append(inflationBuffer, LARGE_BUFFER_SIZE - inflationStream.avail_out);

                length = dynamicInflationBuffer.length();
                return (char *)dynamicInflationBuffer.data();
            }

            length = LARGE_BUFFER_SIZE - inflationStream.avail_out;
            return inflationBuffer;
        }

        template<class T>std::string get_address(T& _socket)
        {
            boost::system::error_code ec;
            auto rt(_socket->lowest_layer().remote_endpoint(ec));
            if (!ec) return rt.address().to_string();
            else return "";
        }
        template<class T> unsigned short get_port(T& _socket)
        {
            boost::system::error_code ec;
            auto rt(_socket->lowest_layer().remote_endpoint(ec));
            if (!ec) return rt.port();
            else return static_cast<unsigned short>(-1);
        }
        template<class T> bool is_v4(T& _socket)
        {
            boost::system::error_code ec;
            auto rt(_socket->lowest_layer().remote_endpoint(ec));
            if (!ec) return rt.address().is_v4();
            else return true;
        }
        template<class T> bool is_v6(T& _socket)
        {
            boost::system::error_code ec;
            auto rt(_socket->lowest_layer().remote_endpoint(ec));
            if (!ec) return rt.address().is_v6();
            else return true;
        }
        template<class T> bool is_loopback(T& _socket)
        {
            boost::system::error_code ec;
            auto rt(_socket->lowest_layer().remote_endpoint(ec));
            if (!ec) return rt.address().is_loopback();
            else return true;
        }

        template<class PARENTTYPE, class SOCKETTYPE> void readexpire_from_now(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, int seconds)
        {

            boost::system::error_code ec;
            if (seconds <= 0) websocket->read_deadline.expires_at(boost::posix_time::pos_infin, ec);
            else  websocket->read_deadline.expires_from_now(boost::posix_time::seconds(seconds), ec);
            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
            }
            else if (seconds >= 0) {
                websocket->read_deadline.async_wait([parent, websocket, socket](const boost::system::error_code& ec) {
                    if (ec != boost::asio::error::operation_aborted) {
                        closesocket(parent, websocket, socket, 1001, "read timer expired on the socket ");
                    }
                });
            }
        }
        template<class PARENTTYPE, class SOCKETTYPE> void writeexpire_from_now(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, int seconds)
        {
            boost::system::error_code ec;
            if (seconds <= 0) websocket->write_deadline.expires_at(boost::posix_time::pos_infin, ec);
            else websocket->write_deadline.expires_from_now(boost::posix_time::seconds(seconds), ec);
            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
            }
            else if (seconds >= 0) {
                websocket->write_deadline.async_wait([parent, websocket, socket, seconds](const boost::system::error_code& ec) {
                    if (ec != boost::asio::error::operation_aborted) {
                        closesocket(parent, websocket, socket, 1001, "write timer expired on the socket ");
                    }
                });
            }
        }
        template<class PARENTTYPE, class SOCKETTYPE>  void closesocket(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, unsigned short code, const std::string& msg)
        {

            size_t sendsize = 2;
            auto msgsize = sizeof(code) + msg.size();
            if (msgsize > 125) {
                msgsize = 125;
            }
            sendsize += msgsize;

            auto header(std::shared_ptr<unsigned char>(new unsigned char[sendsize], [](unsigned char* p) { delete[] p; }));
            setFin(header.get(), 0xFF);
            set_MaskBitForSending<PARENTTYPE>(header.get());
            setOpCode(header.get(), OpCode::CLOSE);
            setrsv1(header.get(), 0x00);
            setrsv2(header.get(), 0x00);
            setrsv3(header.get(), 0x00);

            setpayloadLength1(header.get(), static_cast<unsigned char>(msgsize));
            memcpy(header.get() + 2, &code, sizeof(code));
            memcpy(header.get() + 2 + sizeof(code), msg.c_str(), msgsize - 2 - sizeof(code));

            //writeexpire_from_now(parent, websocket, socket, parent->WriteTimeout);
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sending Close reason: '" << code << "'  msg: '" << msg << "'");
            boost::asio::async_write(*socket, boost::asio::buffer(header.get(), sendsize), [parent, websocket, socket, header, code, msg](const boost::system::error_code&, size_t) {
                if (parent->onDisconnection) {
                    WSocket ws(websocket);
                    if (getOpCode(websocket->ReceiveHeader) == OpCode::CLOSE) {
                        if (websocket->ReceiveBufferSize == 2) {
                            auto code1 = *reinterpret_cast<unsigned short*>(websocket->ReceiveBuffer);
                            parent->onDisconnection(ws, code1, msg);
                        }
                        else if (websocket->ReceiveBufferSize > 2) {
                            auto code1 = *reinterpret_cast<unsigned short*>(websocket->ReceiveBuffer);
                            auto msg1 = std::string(reinterpret_cast<char*>(websocket->ReceiveBuffer) + 2, websocket->ReceiveBufferSize - 2);
                            parent->onDisconnection(ws, code1, msg1);
                        }
                        else {
                            parent->onDisconnection(ws, code, msg);
                        }
                    }
                    else {
                        parent->onDisconnection(ws, code, msg);
                    }
                }
                websocket->canceltimers();
                boost::system::error_code ec;
                socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                ec.clear();
                socket->lowest_layer().close(ec);
            });
        }
        struct WSocketImpl
        {
            WSocketImpl(boost::asio::io_service& s) :read_deadline(s), write_deadline(s) {}
            ~WSocketImpl() {
                canceltimers();
                if (ReceiveBuffer) {
                    free(ReceiveBuffer);
                }
            }
            boost::asio::deadline_timer read_deadline;
            boost::asio::deadline_timer write_deadline;
            unsigned char* ReceiveBuffer = nullptr;
            size_t ReceiveBufferSize = 0;
            unsigned char ReceiveHeader[16];
            bool CompressionEnabled = false;
            std::shared_ptr<boost::asio::ip::tcp::socket> Socket;
            std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> TLSSocket;
            void canceltimers() {
                read_deadline.cancel();
                write_deadline.cancel();
            }
        };
        inline void set_Socket(std::shared_ptr<WSocketImpl>& ws, std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> s) {
            ws->TLSSocket = s;
        }
        inline void set_Socket(std::shared_ptr<WSocketImpl>& ws, std::shared_ptr<boost::asio::ip::tcp::socket>  s) {
            ws->Socket = s;
        }
        struct SendQueueItem {
            std::shared_ptr<WSocketImpl> socket;
            WSSendMessage msg;
        }; 
        struct WSContext {
            WSContext() :
                work(std::make_unique<boost::asio::io_service::work>(io_service)) {
                inflationBuffer = std::make_unique<char[]>(LARGE_BUFFER_SIZE);
                inflateInit2(&inflationStream, -MAX_WBITS);
                io_servicethread = std::thread([&]() {
                    boost::system::error_code ec;
                    io_service.run(ec);
                });

            }
            ~WSContext() {
                SendItems.clear();
                work.reset();
                io_service.stop();
                while (!io_service.stopped()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                if (io_servicethread.joinable()) io_servicethread.join();
                inflateEnd(&inflationStream);
            }
            std::unique_ptr<char[]> inflationBuffer;

            unsigned int ReadTimeout = 30;
            unsigned int WriteTimeout = 30;
            size_t MaxPayload = 1024 * 1024;//1 MB
            std::deque<SendQueueItem> SendItems;
            z_stream inflationStream;
            boost::asio::io_service io_service;
            std::thread io_servicethread;
            std::unique_ptr<boost::asio::io_service::work> work;
            std::unique_ptr<boost::asio::ssl::context> sslcontext;

            std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)> onConnection;
            std::function<void(WSocket&, WSReceiveMessage&)> onMessage;
            std::function<void(WSocket&, unsigned short, const std::string&)> onDisconnection;
            std::function<void(WSocket&, const unsigned char *, size_t)> onPing;
            std::function<void(WSocket&, const unsigned char *, size_t)> onPong;
            std::function<void(WSocket&)> onHttpUpgrade;

        };

        class WSClientImpl : public WSContext {
        public:
            WSClientImpl(std::string Publiccertificate_File)
            {
                sslcontext = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv11);
                std::ifstream file(Publiccertificate_File, std::ios::binary);
                assert(file);
                std::vector<char> buf;
                buf.resize(static_cast<size_t>(filesize(Publiccertificate_File)));
                file.read(buf.data(), buf.size());
                boost::asio::const_buffer cert(buf.data(), buf.size());
                boost::system::error_code ec;
                sslcontext->add_certificate_authority(cert, ec);
                ec.clear();
                sslcontext->set_default_verify_paths(ec);

            }
            WSClientImpl() {  }
            ~WSClientImpl() {}
        };

        class WSListenerImpl : public WSContext {
        public:

            boost::asio::ip::tcp::acceptor acceptor;

            WSListenerImpl(unsigned short port,
                std::string Password,
                std::string Privatekey_File,
                std::string Publiccertificate_File,
                std::string dh_File) :
                WSListenerImpl(port)
            {
                sslcontext = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv11);
                sslcontext->set_options(
                    boost::asio::ssl::context::default_workarounds
                    | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3
                    | boost::asio::ssl::context::single_dh_use);
                boost::system::error_code ec;
                sslcontext->set_password_callback([Password](std::size_t, boost::asio::ssl::context::password_purpose) { return Password; }, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "set_password_callback " << ec.message());
                    ec.clear();
                }
                sslcontext->use_tmp_dh_file(dh_File, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "use_tmp_dh_file " << ec.message());
                    ec.clear();
                }
                sslcontext->use_certificate_chain_file(Publiccertificate_File, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "use_certificate_chain_file " << ec.message());
                    ec.clear();
                }
                sslcontext->set_default_verify_paths(ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "set_default_verify_paths " << ec.message());
                    ec.clear();
                }
                sslcontext->use_private_key_file(Privatekey_File, boost::asio::ssl::context::pem, ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "use_private_key_file " << ec.message());
                    ec.clear();
                }

            }

            WSListenerImpl(unsigned short port) :acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) { }

            ~WSListenerImpl() {
                boost::system::error_code ec;
                acceptor.close(ec);
            }
        };
        /*
        0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-------+-+-------------+-------------------------------+
        |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
        |N|V|V|V|       |S|             |   (if payload len==126/127)   |
        | |1|2|3|       |K|             |                               |
        +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        |     Extended payload length continued, if payload len == 127  |
        + - - - - - - - - - - - - - - - +-------------------------------+
        |                               |Masking-key, if MASK set to 1  |
        +-------------------------------+-------------------------------+
        | Masking-key (continued)       |          Payload Data         |
        +-------------------------------- - - - - - - - - - - - - - - - +
        :                     Payload Data continued ...                :
        + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        |                     Payload Data continued ...                |
        +---------------------------------------------------------------+
        */
        inline bool getFin(unsigned char* frame) { return *frame & 128; }
        inline void setFin(unsigned char* frame, unsigned char val) { *frame |= val & 128; }

        inline bool getMask(unsigned char* frame) { return frame[1] & 128; }
        inline void setMask(unsigned char* frame, unsigned char val) { frame[1] |= val & 128; }

        inline unsigned char getpayloadLength1(unsigned char *frame) { return frame[1] & 127; }
        inline unsigned short getpayloadLength2(unsigned char *frame) { return *reinterpret_cast<unsigned short*>(frame + 2); }
        inline unsigned long long int getpayloadLength8(unsigned char *frame) { return *reinterpret_cast<unsigned long long int*>(frame + 2); }

        inline void setpayloadLength1(unsigned char *frame, unsigned char  val) { frame[1] = val; }
        inline void setpayloadLength2(unsigned char *frame, unsigned short val) { *reinterpret_cast<unsigned short*>(frame + 2) = val; }
        inline void setpayloadLength8(unsigned char *frame, unsigned long long int val) { *reinterpret_cast<unsigned long long int *>(frame + 2) = val; }

        inline OpCode getOpCode(unsigned char *frame) { return static_cast<OpCode>(*frame & 15); }
        inline void setOpCode(unsigned char *frame, OpCode val) { *frame |= val & 15; }

        inline bool getrsv3(unsigned char *frame) { return *frame & 16; }
        inline bool getrsv2(unsigned char *frame) { return *frame & 32; }
        //compressed?
        inline bool getrsv1(unsigned char *frame) { return *frame & 64; }

        inline void setrsv3(unsigned char *frame, unsigned char val) { *frame |= val & 16; }
        inline void setrsv2(unsigned char *frame, unsigned char val) { *frame |= val & 32; }
        inline void setrsv1(unsigned char *frame, unsigned char val) { *frame |= val & 64; }

        struct HandshakeContainer {
            boost::asio::streambuf Read;
            boost::asio::streambuf Write;
            std::unordered_map<std::string, std::string> Header;
        };
        struct WSSendMessageInternal {
            unsigned char* Data;
            unsigned long long int  len;
            OpCode code;
            //compress the outgoing message?
            bool Compress;
        };

        template<class PARENTTYPE>inline bool DidPassMaskRequirement(unsigned char* h) { return true; }
        template<> inline bool DidPassMaskRequirement<WSListenerImpl>(unsigned char* h) { return getMask(h); }
        template<> inline bool DidPassMaskRequirement<WSClientImpl>(unsigned char* h) { return !getMask(h); }

        template<class PARENTTYPE>inline size_t AdditionalBodyBytesToRead() { return 0; }
        template<>inline size_t AdditionalBodyBytesToRead<WSListenerImpl>() { return 4; }
        template<>inline size_t AdditionalBodyBytesToRead<WSClientImpl>() { return 0; }

        template<class PARENTTYPE>inline void set_MaskBitForSending(unsigned char* frame) {  }
        template<>inline void set_MaskBitForSending<WSListenerImpl>(unsigned char* frame) { setMask(frame, 0x00); }
        template<>inline void set_MaskBitForSending<WSClientImpl>(unsigned char* frame) { setMask(frame, 0xff); }


        template<class PARENTYPE, class SOCKETTYPE, class SENDBUFFERTYPE>inline void write_end(const PARENTYPE& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {

            boost::asio::async_write(*socket, boost::asio::buffer(msg.Data, static_cast<size_t>(msg.len)), [parent, websocket, socket, msg](const boost::system::error_code& ec, size_t bytes_transferred) {
                UNUSED(bytes_transferred);
                assert(static_cast<size_t>(msg.len) == bytes_transferred);
                if (!parent->SendItems.empty()) {
                    parent->SendItems.pop_back();
                }
                if (ec)
                {
                    return closesocket(parent, websocket, socket, 1002, "write header failed   " + ec.message());
                }
                else {
                    startwrite(parent);
                }
            });
        }

        template<class SOCKETTYPE, class SENDBUFFERTYPE>inline void writeend(const std::shared_ptr<WSClientImpl>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {
            std::uniform_int_distribution<unsigned int> dist(0, 255);
            std::random_device rd;

            auto mask(std::shared_ptr<char>(new char[4], [](char* p) { delete[] p; }));
            auto maskeddata = mask.get();
            for (auto c = 0; c < 4; c++) {
                maskeddata[c] = static_cast<unsigned char>(dist(rd));
            }
            auto p = reinterpret_cast<unsigned char*>(msg.Data);
            for (decltype(msg.len) i = 0; i < msg.len; i++) {
                *p++ ^= maskeddata[i % 4];
            }

            boost::asio::async_write(*socket, boost::asio::buffer(mask.get(), 4), [parent, websocket, socket, msg](const boost::system::error_code& ec, size_t bytes_transferred) {
                UNUSED(bytes_transferred);
                assert(bytes_transferred == 4);
                if (!ec) {
                    write_end(parent, websocket, socket, msg);
                }
                else {
                    return closesocket(parent, websocket, socket, 1002, "write mask failed  " + ec.message());
                }
            });
        }
        template<class SOCKETTYPE, class SENDBUFFERTYPE>inline void writeend(const std::shared_ptr<WSListenerImpl>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {
            write_end(parent, websocket, socket, msg);
        }

        template<class PARENTTYPE, class SOCKETTYPE, class SENDBUFFERTYPE>inline void write(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const SENDBUFFERTYPE& msg) {
            size_t sendsize = 16;
            auto header(std::shared_ptr<unsigned char>(new unsigned char[sendsize], [](unsigned char* p) { delete[] p; }));
            setFin(header.get(), 0xFF);
            set_MaskBitForSending<PARENTTYPE>(header.get());
            setOpCode(header.get(), msg.code);
            setrsv1(header.get(), 0x00);
            setrsv2(header.get(), 0x00);
            setrsv3(header.get(), 0x00);


            if (msg.len <= 125) {
                setpayloadLength1(header.get(), static_cast<unsigned char>(msg.len));
                sendsize -= 7;
            }
            else if (msg.len > USHRT_MAX) {
                setpayloadLength8(header.get(), msg.len);
                setpayloadLength1(header.get(), 127);
            }
            else {
                setpayloadLength2(header.get(), static_cast<unsigned short>(msg.len));
                setpayloadLength1(header.get(), 126);
                sendsize -= 4;
            }

            assert(msg.len < UINT32_MAX);
            writeexpire_from_now(parent, websocket, socket, parent->WriteTimeout);
            boost::asio::async_write(*socket, boost::asio::buffer(header.get(), sendsize), [parent, socket, websocket, header, msg, sendsize](const boost::system::error_code& ec, size_t bytes_transferred) {
                UNUSED(bytes_transferred);
                if (!ec)
                {
                    assert(sendsize == bytes_transferred);
                    writeend(parent, websocket, socket, msg);
                }
                else {
                    return closesocket(parent, websocket, socket, 1002, "write header failed   " + ec.message());
                }
            });
        }
        template<class PARENTTYPE>inline void startwrite(const std::shared_ptr<PARENTTYPE>& parent) {
            if (!parent->SendItems.empty()) {
                auto msg(parent->SendItems.back());
                if (msg.socket->Socket) {
                    write(parent, msg.socket, msg.socket->Socket, msg.msg);
                }
                else {
                    write(parent, msg.socket, msg.socket->TLSSocket, msg.msg);
                }
            }
        }
        inline void UnMaskMessage(const std::shared_ptr<WSListenerImpl>& parent, const std::shared_ptr<WSocketImpl>& websocket, size_t size) {
            UNUSED(parent);
            auto startp = websocket->ReceiveBuffer + websocket->ReceiveBufferSize - size;
            unsigned char mask[4];
            memcpy(mask, startp, 4);
            for (size_t c = 4; c < size; c++) {
                startp[c] = startp[c] ^ mask[c % 4];
            }
            websocket->ReceiveBufferSize -= 4;//remove the mask as size
        }
        inline void UnMaskMessage(const std::shared_ptr<WSClientImpl>& parent, const std::shared_ptr<WSocketImpl>& websocket, size_t size) {
            UNUSED(parent);
            UNUSED(websocket);
            UNUSED(size);
        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ProcessBody(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, size_t payloadlen) {
            UnMaskMessage(parent, websocket, payloadlen);
            auto opcode = getOpCode(websocket->ReceiveHeader);
            if (!getFin(websocket->ReceiveHeader)) {//not a final frame.. must be either text, binary or continuation
                if (opcode == OpCode::CONTINUATION && websocket->ReceiveBufferSize == 0) {
                    return closesocket(parent, websocket, socket, 1002, "Continuation Received without a previous frame");
                }
                else if (opcode == OpCode::BINARY || opcode == OpCode::TEXT || opcode == OpCode::CONTINUATION) {
                    ReadHeaderNext(parent, websocket, socket);
                }
                else {
                    return closesocket(parent, websocket, socket, 1002, "Only Binary, Text or continuation are valid on non fin msgs");
                }
            }
            else {
                WSocket wsocket(websocket);
                switch (opcode)
                {
                case OpCode::PING:
                    if (parent->onPing) {
                        parent->onPing(wsocket, websocket->ReceiveBuffer, websocket->ReceiveBufferSize);
                    }
                    auto sendmessage = WSSendMessageInternal{ websocket->ReceiveBuffer,  websocket->ReceiveBufferSize, OpCode::PONG, false };
                    SL::WS_LITE::write(parent, websocket, socket, sendmessage);
                    break;
                case OpCode::PONG:
                    if (parent->onPong) {
                        parent->onPong(wsocket, websocket->ReceiveBuffer, websocket->ReceiveBufferSize);
                    }
                    break;
                case OpCode::CLOSE:
                    return closesocket(parent, websocket, socket, 1000, "Close requested by the other side");
                case OpCode::CONTINUATION:
                    if (websocket->ReceiveBufferSize == 0) {
                        return closesocket(parent, websocket, socket, 1002, "Continuation Received without a previous frame");
                    }

                default:
                    if (parent->onMessage) {
                        auto unpacked = WSReceiveMessage{ websocket->ReceiveBuffer,  websocket->ReceiveBufferSize, getOpCode(websocket->ReceiveHeader) };
                        parent->onMessage(wsocket, unpacked);
                    }
                    ReadHeaderStart(parent, websocket, socket);
                    break;
                }
            }

        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadBody(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, size_t payloadlen) {

            readexpire_from_now(parent, websocket, socket, parent->ReadTimeout);
            size_t size = 0;

            switch (payloadlen) {
            case 2:
                size = swap_endian(getpayloadLength2(websocket->ReceiveHeader));
                break;
            case 8:
                if (swap_endian(getpayloadLength8(websocket->ReceiveHeader)) > std::numeric_limits<std::size_t>::max()) {
                    return closesocket(parent, websocket, socket, 1009, "Payload exceeded MaxPayload size");
                }
                size = static_cast<size_t>(swap_endian(getpayloadLength8(websocket->ReceiveHeader)));
                break;
            default:
                size = getpayloadLength1(websocket->ReceiveHeader);
            }
            auto opcode = getOpCode(websocket->ReceiveHeader);
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadBody size " << size << " opcode " << opcode);
            if ((opcode == OpCode::PING || opcode == OpCode::PONG || opcode == OpCode::CLOSE) && size > 125) {
                return closesocket(parent, websocket, socket, 1002, "Payload exceeded for control frames. Size requested " + std::to_string(size));
            }
            size += AdditionalBodyBytesToRead<PARENTTYPE>();

            auto addedsize = static_cast<unsigned long long int>(websocket->ReceiveBufferSize) + static_cast<unsigned long long int>(size);
            if (addedsize > std::numeric_limits<std::size_t>::max()) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "payload exceeds memory on system!!! ");
                return closesocket(parent, websocket, socket, 1009, "Payload exceeded MaxPayload size");
            }
            websocket->ReceiveBufferSize = static_cast<size_t>(addedsize);


            if (websocket->ReceiveBufferSize > parent->MaxPayload) {
                return closesocket(parent, websocket, socket, 1009, "Payload exceeded MaxPayload size");
            }
            if (websocket->ReceiveBufferSize > std::numeric_limits<std::size_t>::max()) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "payload exceeds memory on system!!! ");
                return closesocket(parent, websocket, socket, 1009, "Payload exceeded MaxPayload size");
            }

            if (size > 0) {
                websocket->ReceiveBuffer = static_cast<unsigned char*>(realloc(websocket->ReceiveBuffer, websocket->ReceiveBufferSize));
                if (!websocket->ReceiveBuffer) {
                    SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "MEMORY ALLOCATION ERROR!!!");
                    return closesocket(parent, websocket, socket, 1009, "Payload exceeded MaxPayload size");
                }
                boost::asio::async_read(*socket, boost::asio::buffer(websocket->ReceiveBuffer + websocket->ReceiveBufferSize - size, size), [parent, websocket, socket, size](const boost::system::error_code& ec, size_t bytes_transferred) {

                    if (!ec) {
                        assert(size == bytes_transferred);
                        if (size != bytes_transferred) {
                            return closesocket(parent, websocket, socket, 1002, "Did not receive all bytes ... ");
                        }
                        ProcessBody(parent, websocket, socket, size);
                    }
                    else {
                        return closesocket(parent, websocket, socket, 1002, "ReadBody Error " + ec.message());
                    }
                });
            }
            else {
                ProcessBody(parent, websocket, socket, size);
            }
        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadHeaderStart(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket) {
            free(websocket->ReceiveBuffer);
            websocket->ReceiveBuffer = nullptr;
            websocket->ReceiveBufferSize = 0;
            ReadHeaderNext(parent, websocket, socket);
        }
        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadHeaderNext(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket) {
            readexpire_from_now(parent, websocket, socket, parent->ReadTimeout);
            boost::asio::async_read(*socket, boost::asio::buffer(websocket->ReceiveHeader, 2), [parent, websocket, socket](const boost::system::error_code& ec, size_t bytes_transferred) {
                UNUSED(bytes_transferred);
                if (!ec) {
                    assert(bytes_transferred == 2);
                    if (!DidPassMaskRequirement<PARENTTYPE>(websocket->ReceiveHeader)) {//Close connection if it did not meet the mask requirement. 
                        return closesocket(parent, websocket, socket, 1002, "Closing connection because mask requirement not met");
                    }
                    else {
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

                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadHeader readbytes " << readbytes);
                        if (readbytes > 1) {
                            boost::asio::async_read(*socket, boost::asio::buffer(websocket->ReceiveHeader + 2, readbytes), [parent, websocket, socket, readbytes](const boost::system::error_code& ec, size_t bytes_transferred) {
                                if (readbytes != bytes_transferred) {
                                    return closesocket(parent, websocket, socket, 1002, "Did not receive all bytes ... ");
                                }
                                else if (!ec) {
                                    ReadBody(parent, websocket, socket, readbytes);
                                }
                                else {
                                    return closesocket(parent, websocket, socket, 1002, "readheader ExtendedPayloadlen " + ec.message());
                                }
                            });
                        }
                        else {
                            ReadBody(parent, websocket, socket, readbytes);
                        }
                    }
                }
                else {
                    return closesocket(parent, websocket, socket, 1002, "WebSocket ReadHeader failed " + ec.message());
                }
            });
        }
    }
}