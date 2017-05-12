#pragma once
#include "WS_Lite.h"
#include "internal/Utils.h"
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

namespace SL {
    namespace WS_LITE {
        template<class PARENT, class SOCKETTYPE>void Disconnect(const PARENT& parent, SOCKETTYPE& websocket, const std::string& msg)
        {

            if (parent->onDisconnection) {
                auto wsdisc = WSReceiveMessage{ msg.c_str(), msg.size(), OpCode::TEXT };
                WSocket wsocket(websocket);
                parent->onDisconnection(wsocket, wsdisc);
            }
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, msg);
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

        template<class T> void readexpire_from_now(T self, int seconds)
        {
            boost::system::error_code ec;
            if (seconds <= 0) self->read_deadline.expires_at(boost::posix_time::pos_infin, ec);
            else  self->read_deadline.expires_from_now(boost::posix_time::seconds(seconds), ec);
            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
            }
            else if (seconds >= 0) {
                self->read_deadline.async_wait([self, seconds](const boost::system::error_code& ec) {
                    if (ec != boost::asio::error::operation_aborted) {
                        //self->close("read timer expired. Time waited: ");
                    }
                });
            }
        }
        template<class T> void writeexpire_from_now(T self, int seconds)
        {
            boost::system::error_code ec;
            if (seconds <= 0) self->write_deadline.expires_at(boost::posix_time::pos_infin, ec);
            else self->write_deadline.expires_from_now(boost::posix_time::seconds(seconds), ec);
            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, ec.message());
            }
            else if (seconds >= 0) {
                self->write_deadline.async_wait([self, seconds](const boost::system::error_code& ec) {
                    if (ec != boost::asio::error::operation_aborted) {
                        //close("write timer expired. Time waited: " + std::to_string(seconds));
                        //self->close("write timer expired. Time waited: ");
                    }
                });
            }
        }

        struct WSocketImpl
        {
            WSocketImpl(boost::asio::io_service& s) :read_deadline(s), write_deadline(s) {}
            ~WSocketImpl() {
                read_deadline.cancel();
                write_deadline.cancel();
            }
            boost::asio::deadline_timer read_deadline;
            boost::asio::deadline_timer write_deadline;
            std::shared_ptr<boost::asio::ip::tcp::socket> Socket;
            std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> TLSSocket;

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
            }

            unsigned int ReadTimeout = 5;
            unsigned int WriteTimeout = 5;
            unsigned long long int MaxPayload = 1024 * 1024;//1 MB
            std::deque<SendQueueItem> SendItems;

            boost::asio::io_service io_service;
            std::thread io_servicethread;
            std::unique_ptr<boost::asio::io_service::work> work;
            std::unique_ptr<boost::asio::ssl::context> sslcontext;

            std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)> onConnection;
            std::function<void(WSocket&, WSReceiveMessage&)> onMessage;
            std::function<void(WSocket&, WSReceiveMessage&)> onDisconnection;
            std::function<void(WSocket&, char *, size_t)> onPing;
            std::function<void(WSocket&, char *, size_t)> onPong;
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
        inline bool getrsv1(unsigned char *frame) { return *frame & 64; }

        inline void setrsv3(unsigned char *frame, unsigned char val) { *frame |= val & 16; }
        inline void setrsv2(unsigned char *frame, unsigned char val) { *frame |= val & 32; }
        inline void setrsv1(unsigned char *frame, unsigned char val) { *frame |= val & 64; }

        struct HandshakeContainer {
            boost::asio::streambuf Read;
            boost::asio::streambuf Write;
            std::unordered_map<std::string, std::string> Header;
        };

        template<class PARENTTYPE>inline bool DidPassMaskRequirement(const std::shared_ptr<unsigned char>& h) { return true; }
        template<> inline bool DidPassMaskRequirement<WSListenerImpl>(const std::shared_ptr<unsigned char>& h) { return getMask(h.get()); }
        template<> inline bool DidPassMaskRequirement<WSClientImpl>(const std::shared_ptr<unsigned char>& h) { return !getMask(h.get()); }

        template<class PARENTTYPE>inline unsigned long long int AdditionalBodyBytesToRead() { return 0; }
        template<>inline unsigned long long int AdditionalBodyBytesToRead<WSListenerImpl>() { return 4; }
        template<>inline unsigned long long int AdditionalBodyBytesToRead<WSClientImpl>() { return 0; }

        template<class PARENTTYPE>inline void set_MaskBitForSending(unsigned char* frame) {  }
        template<>inline void set_MaskBitForSending<WSListenerImpl>(unsigned char* frame) { setMask(frame, 0x00); }
        template<>inline void set_MaskBitForSending<WSClientImpl>(unsigned char* frame) { setMask(frame, 0xff); }

        inline void ProcessMessage(const std::shared_ptr<WSListenerImpl>& parent, const std::shared_ptr<char>& buffer, unsigned long long int size, const std::shared_ptr<WSocketImpl>& websocket, const std::shared_ptr<unsigned char>& header) {
            unsigned char mask[4];
            memcpy(mask, buffer.get(), 4);
            auto p = buffer.get() + 4;
            for (decltype(size) c = 0; c < size - 4; c++) {
                p[c] = p[c] ^ mask[c % 4];
            }
            auto unpacked = WSReceiveMessage{ p, size - 4, getOpCode(header.get()) };
            WSocket ws(websocket);
            parent->onMessage(ws, unpacked);
        }
        inline void ProcessMessage(const std::shared_ptr<WSClientImpl>& parent, const std::shared_ptr<char>& buffer, unsigned long long int  size, const std::shared_ptr<WSocketImpl>& websocket, const std::shared_ptr<unsigned char>& header) {
            auto unpacked = WSReceiveMessage{ buffer.get(), size, getOpCode(header.get()) };
            WSocket ws(websocket);
            parent->onMessage(ws, unpacked);
        }

        template<class SOCKETTYPE>inline void writeend(const std::shared_ptr<WSClientImpl>& parent, const std::shared_ptr<WSocketImpl>& socket, const SOCKETTYPE& websocket, const WSSendMessage& msg) {
            UNUSED(parent);
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

            boost::asio::async_write(*websocket, boost::asio::buffer(mask.get(), 4), [parent, websocket, socket, msg](const boost::system::error_code& ec, size_t bytes_transferred) {
                assert(bytes_transferred == 4);
                if (!ec) {
                    boost::asio::async_write(*websocket, boost::asio::buffer(msg.Data, static_cast<size_t>(msg.len)), [parent, websocket, socket, msg](const boost::system::error_code& ec, size_t bytes_transferred) {
                        assert(static_cast<size_t>(msg.len) == bytes_transferred);
                        if (!parent->SendItems.empty()) {
                            parent->SendItems.pop_back();
                        }
                        if (ec) {
                            WSocket ws(socket);
                            return Disconnect(parent, ws, "write payload failed " + ec.message());
                        }
                        else {
                            startwrite(parent);
                        }
                    });
                }
                else {
                    WSocket ws(socket);
                    return Disconnect(parent, ws, "write mask failed  " + ec.message());
                }
            });
        }
        template<class SOCKETTYPE>inline void writeend(const std::shared_ptr<WSListenerImpl>& parent, const std::shared_ptr<WSocketImpl>& socket, const SOCKETTYPE& websocket, const WSSendMessage& msg) {
            UNUSED(parent);
            boost::asio::async_write(*websocket, boost::asio::buffer(msg.Data, static_cast<size_t>(msg.len)), [parent, websocket, socket, msg](const boost::system::error_code& ec, size_t bytes_transferred) {
                assert(static_cast<size_t>(msg.len) == bytes_transferred);
                if (!parent->SendItems.empty()) {
                    parent->SendItems.pop_back();
                }

                if (ec)
                {
                    WSocket ws(socket);
                    return Disconnect(parent, ws, "write header failed " + ec.message());
                }
                else {
                    startwrite(parent);
                }
            });
        }

        template<class PARENTTYPE, class SOCKETTYPE>inline void write(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& socket, const SOCKETTYPE& websocket, const WSSendMessage& msg) {
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
            writeexpire_from_now(socket, parent->WriteTimeout);
            boost::asio::async_write(*websocket, boost::asio::buffer(header.get(), sendsize), [parent, websocket, socket, header, msg, sendsize](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec)
                {  
                    assert(sendsize == bytes_transferred);
                    writeend(parent, socket, websocket, msg);
                }
                else {
                    WSocket ws(socket);
                    return Disconnect(parent, ws, "write header failed " + ec.message());
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
        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadBody(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket, const std::shared_ptr<unsigned char>& header, size_t payloadlen) {

            readexpire_from_now(websocket, parent->ReadTimeout);
            unsigned long long int size = 0;
            switch (payloadlen) {
            case 2:
                size = swap_endian(getpayloadLength2(header.get()));
                break;
            case 8:
                size = swap_endian(getpayloadLength8(header.get()));
                break;
            default:
                size = getpayloadLength1(header.get());
            }
            auto opcode = getOpCode(header.get());
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadBody size "<<size << " opcode "<< opcode);
            if ((opcode == OpCode::PING || opcode == OpCode::PONG || opcode == OpCode::CLOSE) && size > 125) {
                return Disconnect(parent, websocket, "Payload exceeded for control frames. Size requested " + std::to_string(size));
            }
            if (opcode == OpCode::CONTINUATION) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "CONTINUATION ");
            }
            if (opcode == OpCode::CLOSE) {
                return Disconnect(parent, websocket, "Close requested ");
            }
            size += AdditionalBodyBytesToRead<PARENTTYPE>();
            if (size > parent->MaxPayload) {
                return Disconnect(parent, websocket, "Payload exceeded MaxPayload size");
            }
            if (size > 0) {
                auto buffer = std::shared_ptr<char>(new char[static_cast<size_t>(size)], [](char * p) { delete[] p; });
                boost::asio::async_read(*socket, boost::asio::buffer(buffer.get(), static_cast<size_t>(size)), [parent, websocket, socket, header, buffer, size](const boost::system::error_code& ec, size_t bytes_transferred) {
                    WSocket wsocket(websocket);
                    if (!ec) {
                        assert(size == bytes_transferred);
                        if (size != bytes_transferred) {
                            return Disconnect(parent, websocket, "readbytes != bytes_transferred ");
                        }
                        else if (getOpCode(header.get()) == OpCode::PING) {
                            if (parent->onPing) {
                                parent->onPing(wsocket, buffer.get() + 4, static_cast<size_t>(size - 4));
                            }
                            auto sendmessage = WSSendMessage{ buffer ,buffer.get() + 4, size - 4, OpCode::PONG };
                            SL::WS_LITE::write(parent, websocket, socket, sendmessage);
                        }
                        else if (getOpCode(header.get()) == OpCode::PONG) {
                            if (parent->onPong) {
                                parent->onPong(wsocket, buffer.get() + 4, static_cast<size_t>(size - 4));
                            }
                        }
                        else if (parent->onMessage) {
                            ProcessMessage(parent, buffer, size, websocket, header);
                        }
                        ReadHeader(parent, websocket, socket);
                    }
                    else {
                        return Disconnect(parent, wsocket, "ReadBody Error " + ec.message());
                    }
                });
            }
            else {
                std::shared_ptr<char> buffer;
                WSocket wsocket(websocket);
                if (opcode == OpCode::PING) {
                    if (parent->onPing) {
                        parent->onPing(wsocket, nullptr, 0);
                    }
                    auto sendmessage = WSSendMessage{ buffer  ,nullptr, 0, OpCode::PONG };
                    SL::WS_LITE::write(parent, websocket, socket, sendmessage);
                }
                else if (opcode == OpCode::PONG) {
                    if (parent->onPong) {
                        parent->onPong(wsocket, nullptr, 0);
                    }
                }
                else if (parent->onMessage) {
                    ProcessMessage(parent, buffer, 0, websocket, header);
                }
                ReadHeader(parent, websocket, socket);
            }
        }

        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadHeader(const std::shared_ptr<PARENTTYPE>& parent, const std::shared_ptr<WSocketImpl>& websocket, const SOCKETTYPE& socket) {
            readexpire_from_now(websocket, 0);
            auto buff(std::shared_ptr<unsigned char>(new unsigned char[16], [](unsigned char *p) { delete[] p; }));
            boost::asio::async_read(*socket, boost::asio::buffer(buff.get(), 2), [parent, websocket, socket, buff](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    assert(bytes_transferred == 2);

                    if (!DidPassMaskRequirement<PARENTTYPE>(buff)) {//Close connection if it did not meet the mask requirement. 
                        return Disconnect(parent, websocket, "Closing connection because mask requirement not met");
                    }
                    else {
                        size_t readbytes = getpayloadLength1(buff.get());
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
                            boost::asio::async_read(*socket, boost::asio::buffer(buff.get() + 2, readbytes), [parent, websocket, socket, buff, readbytes](const boost::system::error_code& ec, size_t bytes_transferred) {
                                if (readbytes != bytes_transferred) {
                                    return Disconnect(parent, websocket, "readbytes != bytes_transferred");
                                }
                                else if (!ec) {
                                    ReadBody(parent, websocket, socket, buff, readbytes);
                                }
                                else {
                                    return Disconnect(parent, websocket, "readheader ExtendedPayloadlen " + ec.message());
                                }
                            });
                        }
                        else {
                            ReadBody(parent, websocket, socket, buff, readbytes);
                        }
                    }
                }
                else {
                    return Disconnect(parent, websocket, "WebSocket ReadHeader failed " + ec.message());
                }
            });
        }


    }
}