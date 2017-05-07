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

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
    namespace WS_LITE {
        template<class PARENT, class SOCKETTYPE>void Disconnect(const PARENT& parent, const SOCKETTYPE& websocket, const std::string& msg)
        {
            if (parent->onDisconnection) {
                auto wsdisc = WSReceiveMessage{ msg.c_str(), msg.size(),OpCode::TEXT };
                parent->onDisconnection(websocket, wsdisc);
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

        struct WSContext {
            WSContext() :
                work(std::make_unique<boost::asio::io_service::work>(io_service)) {
                io_servicethread = std::thread([&]() {
                    boost::system::error_code ec;
                    io_service.run(ec);
                });

            }
            ~WSContext() {
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

            boost::asio::io_service io_service;
            std::thread io_servicethread;
            std::unique_ptr<boost::asio::io_service::work> work;
            std::unique_ptr<boost::asio::ssl::context> sslcontext;

            std::function<void(WSocket, const std::unordered_map<std::string, std::string>&)> onConnection;
            std::function<void(WSocket, WSReceiveMessage&)> onMessage;
            std::function<void(WSocket, WSReceiveMessage&)> onDisconnection;
            std::function<void(WSocket, char *, size_t)> onPing;
            std::function<void(WSocket, char *, size_t)> onPong;
            std::function<void(WSocket)> onHttpUpgrade;

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

        struct WSHeader {
            bool FIN : 1;
            bool RSV1 : 1;
            bool RSV2 : 1;
            bool RSV3 : 1;
            OpCode Opcode : 4;
            bool Mask : 1;//all frames sent from client to server should have mask data
            unsigned char Payloadlen : 7;
            union {
                unsigned short ShortPayloadlen;
                unsigned long long int ExtendedPayloadlen;
            };
        };
        struct HandshakeContainer {
            boost::asio::streambuf Read;
            boost::asio::streambuf Write;
            std::unordered_map<std::string, std::string> Header;
        };

        template<class PARENTTYPE>inline bool DidPassMaskRequirement(const std::shared_ptr<WSHeader>& h) { return h->Mask; }
        template<> inline bool DidPassMaskRequirement<WSListenerImpl>(const std::shared_ptr<WSHeader>& h) { return h->Mask; }
        template<> inline bool DidPassMaskRequirement<WSClientImpl>(const std::shared_ptr<WSHeader>& h) { return !h->Mask; }

        template<class PARENTTYPE>inline unsigned long long int AdditionalBodyBytesToRead() { return 0; }
        template<>inline unsigned long long int AdditionalBodyBytesToRead<WSListenerImpl>() { return 4; }
        template<>inline unsigned long long int AdditionalBodyBytesToRead<WSClientImpl>() { return 0; }

        template<class PARENTTYPE>inline void set_MaskBitForSending(WSHeader& header) {  }
        template<>inline void set_MaskBitForSending<WSListenerImpl>(WSHeader& header) { header.Mask = false; }
        template<>inline void set_MaskBitForSending<WSClientImpl>(WSHeader& header) { header.Mask = true; }

        inline void ProcessMessage(const std::shared_ptr<WSListenerImpl>& parent, const std::shared_ptr<char>& buffer, unsigned long long int size, const std::shared_ptr<WSocketImpl>& websocket, const std::shared_ptr<WSHeader>& header) {
            unsigned char mask[4];
            memcpy(mask, buffer.get(), 4);
            auto p = buffer.get() + 4;
            for (decltype(size) c = 0; c < size - 4; c++) {
                p[c] = p[c] ^ mask[c % 4];
            }
            auto unpacked = WSReceiveMessage{ p, size - 4, header->Opcode };
            WSocket ws(websocket);
            parent->onMessage(ws, unpacked);
        }
        inline void ProcessMessage(const std::shared_ptr<WSClientImpl>& parent, const std::shared_ptr<char>& buffer, unsigned long long int  size, const std::shared_ptr<WSocketImpl>& websocket, const std::shared_ptr<WSHeader>& header) {
            auto unpacked = WSReceiveMessage{ buffer.get(), size, header->Opcode };
            WSocket ws(websocket);
            parent->onMessage(ws, unpacked);
        }

        size_t inline GetPayloadBytes(WSHeader* buff) { return (buff->Payloadlen & 127) == 126 ? 2 : ((buff->Payloadlen & 127) == 127 ? 8 : 1); }

        template<class SOCKETTYPE>inline void send(const std::shared_ptr<WSClientImpl>& parent, SOCKETTYPE& websocket, WSSendMessage& msg, WSocket& ws) {
            UNUSED(parent);
            std::uniform_int_distribution<unsigned int> dist(0, 255);
            std::random_device rd;
            unsigned char mask[4];
            for (size_t c = 0; c < sizeof(mask); c++) {
                mask[c] = static_cast<unsigned char>(dist(rd));
            }
            auto p = reinterpret_cast<unsigned char*>(msg.data);
            for (decltype(msg.len) i = 0; i < msg.len; i++) {
                *p++ ^= mask[i % sizeof(mask)];
            }

            boost::system::error_code ec;
            auto bytes_written = boost::asio::write(*websocket, boost::asio::buffer(mask, sizeof(mask)), ec);
            if (!ec) {
                bytes_written = boost::asio::write(*websocket, boost::asio::buffer(p, static_cast<size_t>(msg.len)), ec);
                if (ec) {
                    return Disconnect(parent, ws, "write payload failed " + ec.message());
                }
            }
            else {
                return Disconnect(parent, ws, "write mask failed  " + ec.message());
            }
        }

        template<class SOCKETTYPE>inline void send(const std::shared_ptr<WSListenerImpl>& parent, SOCKETTYPE& websocket, WSSendMessage& msg, WSocket& ws) {
            UNUSED(parent);
            boost::system::error_code ec;
            auto bytes_written = boost::asio::write(*websocket, boost::asio::buffer(msg.data, static_cast<size_t>(msg.len)), ec);
            if (ec) {
                return Disconnect(parent, ws, "write payload failed " + ec.message());
            }
        }


        template<class PARENTTYPE, class SOCKETTYPE>inline void send(std::shared_ptr<PARENTTYPE> parent, std::shared_ptr<WSocketImpl> s, SOCKETTYPE& websocket, WSSendMessage& msg) {
            
            WSHeader header;
            header.FIN = true;
            set_MaskBitForSending<PARENTTYPE>(header);
            header.Opcode = msg.code;
            header.RSV1 = header.RSV2 = header.RSV3 = false;
            size_t sendsize = sizeof(header);
            if (msg.len <= 125) {
                header.Payloadlen = static_cast<unsigned char>(msg.len);
                sendsize -= 7;
            }
            else if (msg.len > USHRT_MAX) {
                header.ExtendedPayloadlen = msg.len;
                header.Payloadlen = 127;
            }
            else {
                header.Payloadlen = 126;
                header.ShortPayloadlen = static_cast<unsigned short>(msg.len);
                sendsize -= 4;
            }

            assert(msg.len < UINT32_MAX);
            writeexpire_from_now(s, parent->WriteTimeout);
            boost::system::error_code ec;
            auto bytes_written = boost::asio::write(*websocket, boost::asio::buffer(&header, sendsize), ec);
            assert(bytes_written == sizeof(sendsize));

            WSocket ws(s);
            if (!ec)
            {
                send(parent, websocket, msg, ws);
            }
            else {
                return Disconnect(parent, ws, "write header failed " + ec.message());
            }
        }

        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadBody(std::shared_ptr<PARENTTYPE> parent, std::shared_ptr<WSocketImpl> websocket, SOCKETTYPE socket, std::shared_ptr<WSHeader> header) {

            readexpire_from_now(websocket, parent->ReadTimeout);
            unsigned long long int size = 0;
            switch (GetPayloadBytes(header.get())) {
            case 1:
                size = static_cast<unsigned long long int>(header->Payloadlen);
                break;
            case 2:
                size = static_cast<unsigned long long int>(swap_endian(header->ShortPayloadlen));
                break;
            case 8:
                size = static_cast<unsigned long long int>(swap_endian(header->ExtendedPayloadlen));
                break;
            default:
                return Disconnect(parent, websocket, "Incorrect Payload size received");
            }

            auto buffer = std::shared_ptr<char>(new char[static_cast<size_t>(size)], [](char * p) { delete[] p; });
            if ((header->Opcode == OpCode::PING || header->Opcode == OpCode::PONG || header->Opcode == OpCode::CLOSE) && size > 125) {
                return Disconnect(parent, websocket, "Payload exceeded for control frames. Size requested " + std::to_string(size));
            }
            size += AdditionalBodyBytesToRead<PARENTTYPE>();
            if (size > parent->MaxPayload) {
                return Disconnect(parent, websocket, "Payload exceeded MaxPayload size");
            }
            boost::asio::async_read(*socket, boost::asio::buffer(buffer.get(), static_cast<size_t>(size)), [parent, websocket, socket, header, buffer, size](const boost::system::error_code& ec, size_t bytes_transferred) {
                WSocket wsocket(websocket);
                if (!ec) {
                    if (size != bytes_transferred) {
                        return Disconnect(parent, websocket, "readbytes != bytes_transferred ");
                    }
                    else if (header->Opcode == OpCode::PING) {
                        if (parent->onPing) {
                            parent->onPing(wsocket, buffer.get() + 4, static_cast<size_t>(size - 4));
                        }
                        auto unpacked = WSSendMessage{ buffer.get() + 4, size - 4, OpCode::PONG };
                        send(parent, websocket, socket, unpacked);
                    }
                    else if (header->Opcode == OpCode::PONG) {
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

        template <class PARENTTYPE, class SOCKETTYPE>inline void ReadHeader(std::shared_ptr<PARENTTYPE> parent, std::shared_ptr<WSocketImpl> websocket, SOCKETTYPE socket) {
            readexpire_from_now(websocket, 0);
            auto buff = std::make_shared<WSHeader>();
            boost::asio::async_read(*socket, boost::asio::buffer(buff.get(), 2), [parent, websocket, socket, buff](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    assert(bytes_transferred == 2);

                    if (!DidPassMaskRequirement<PARENTTYPE>(buff)) {//Close connection if it did not meet the mask requirement. 
                        return Disconnect(parent, websocket, "Closing connection because mask requirement not met");
                    }
                    else {
                        auto readbytes = GetPayloadBytes(buff.get());
                        if (readbytes > 1) {
                            boost::asio::async_read(*socket, boost::asio::buffer(&buff->ExtendedPayloadlen, readbytes), [parent, websocket, socket, buff, readbytes](const boost::system::error_code& ec, size_t bytes_transferred) {
                                if (readbytes != bytes_transferred) {
                                    return Disconnect(parent, websocket, "readbytes != bytes_transferred");
                                }
                                else if (!ec) {
                                    ReadBody(parent, websocket, socket, buff);
                                }
                                else {
                                    return Disconnect(parent, websocket, "readheader ExtendedPayloadlen " + ec.message());
                                }
                            });
                        }
                        else {
                            ReadBody(parent, websocket, socket, buff);
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