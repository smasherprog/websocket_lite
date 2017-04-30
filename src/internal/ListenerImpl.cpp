#include "WS_Lite.h"
#include "Logging.h"
#include "internal/WebSocketProtocol.h"

namespace SL {
    namespace WS_LITE {


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

        template<class SOCKETTYPE>void send(const std::shared_ptr<WSListenerImpl>& l, WSocket w, SOCKETTYPE& socket, WSSendMessage& msg) {

            WSHeader header;
            header.FIN = true;
            header.Mask = false;
            header.Opcode = msg.code;
            header.RSV1 = header.RSV2 = header.RSV3 = false;
            if (msg.len <= 125) {
                header.Payloadlen = static_cast<unsigned char>(msg.len);
            }
            else if (msg.len > USHRT_MAX) {
                header.ExtendedPayloadlen = msg.len;
                header.Payloadlen = 127;
            }
            else {
                header.Payloadlen = 126;
                header.ShortPayloadlen = static_cast<unsigned short>(msg.len);
            }
            assert(msg.len < UINT32_MAX);
            writeexpire_from_now(w.WSocketImpl_, l->WriteTimeout);
            boost::system::error_code ec;
            auto bytes_written = boost::asio::write(*socket, boost::asio::buffer(&header, sizeof(header)), ec);
            assert(bytes_written == sizeof(header));
            if (!ec)
            {
                ec.clear();
                bytes_written = boost::asio::write(*socket, boost::asio::buffer(msg.data, static_cast<size_t>(msg.len)), ec);
                if (ec) {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "write body failed " << ec.message());
                }
            }
            else {
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "write header failed " << ec.message());
            }
        }
        template <class SOCKETTYPE>void ReadBody(std::shared_ptr<WSListenerImpl> listener, WSocket websocket, SOCKETTYPE socket, std::shared_ptr<WSHeader> header) {

            readexpire_from_now(websocket.WSocketImpl_, listener->ReadTimeout);
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
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Incorrect Payload size received ");
                return;
            }

            auto buffer = std::shared_ptr<char>(new char[static_cast<size_t>(size)], [](char * p) { delete[] p; });
            if ((header->Opcode == OpCode::PING || header->Opcode == OpCode::PONG || header->Opcode == OpCode::CLOSE) && size > 125) {
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Payload exceeded for control frames. Size requested " << size);
                return;
            }
            size += 4;
            if (size > listener->MaxPayload) {
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Payload exceeded MaxPayload size ");
                return;
            }

            boost::asio::async_read(*socket, boost::asio::buffer(buffer.get(), static_cast<size_t>(size)), [listener, websocket, socket, header, buffer, size](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    if (size != bytes_transferred) {
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "size != bytes_transferred");
                        return;
                    }
                    else if (header->Opcode == OpCode::PING) {
                        if (listener->onPing) {
                            listener->onPing(websocket, buffer.get() + 4, static_cast<size_t>(size - 4));
                        }
                        auto unpacked = WSSendMessage{ buffer.get() + 4, size - 4, OpCode::PONG };
                        send(listener,websocket, socket,unpacked);
                    }
                    else if (header->Opcode == OpCode::PONG) {
                        if (listener->onPong) {
                            listener->onPong(websocket, buffer.get() + 4, static_cast<size_t>(size - 4));
                        }
                    }
                    else if (listener->onMessage) {
                        unsigned char mask[4];
                        memcpy(mask, buffer.get(), 4);
                        auto p = buffer.get() + 4;
                        for (decltype(size) c = 0; c < size - 4; c++) {
                            p[c] = p[c] ^ mask[c % 4];
                        }
                        auto unpacked = WSReceiveMessage{ p, size - 4, header->Opcode };
                        listener->onMessage(websocket, unpacked);
                    }
                    ReadHeader(listener, websocket, socket);
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadBody " << ec.message());
                }
            });
        }
        template <class SOCKETTYPE>void ReadHeader(std::shared_ptr<WSListenerImpl> listener, WSocket websocket, SOCKETTYPE socket) {
            readexpire_from_now(websocket.WSocketImpl_, 0);
            auto buff = std::make_shared<WSHeader>();
            boost::asio::async_read(*socket, boost::asio::buffer(buff.get(), 2), [listener, websocket, socket, buff](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    assert(bytes_transferred == 2);
                    if (!buff->Mask) {//Close connection if unmasked message from client (protocol error)
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Closing connection because mask was not received ");
                    }
                    else {
                        auto readbytes = GetPayloadBytes(buff.get());
                        if (readbytes > 1) {
                            boost::asio::async_read(*socket, boost::asio::buffer(&buff->ExtendedPayloadlen, readbytes), [listener, websocket, socket, buff, readbytes](const boost::system::error_code& ec, size_t bytes_transferred) {
                                if (readbytes != bytes_transferred) {
                                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "readbytes != bytes_transferred ");
                                }
                                else if (!ec) {
                                    ReadBody(listener, websocket, socket, buff);
                                }
                                else {
                                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "readheader ExtendedPayloadlen " << ec.message());
                                }
                            });
                        }
                        else {
                            ReadBody(listener, websocket, socket, buff);
                        }
                    }
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadHeader Failed: " << ec.message());
                }
            });
        }
        template<class SOCKETTYPE>void read_handshake(std::shared_ptr<WSListenerImpl> listener, SOCKETTYPE& socket) {
            auto read_buffer(std::make_shared<boost::asio::streambuf>());
            boost::asio::async_read_until(*socket, *read_buffer, "\r\n\r\n", [listener, socket, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);

                    std::istream stream(read_buffer.get());
                    auto header = Parse_Handshake("1.1", stream);

                    auto write_buffer(std::make_shared<boost::asio::streambuf>());
                    std::ostream handshake(write_buffer.get());
                    if (Generate_Handshake(header, handshake)) {
                        WSocket websocket;
                        websocket.WSocketImpl_ = std::make_shared<WSocketImpl>(listener->io_service);
                        set_Socket(websocket, socket);
                        if (listener->onHttpUpgrade) {
                            listener->onHttpUpgrade(websocket);
                        }

                        boost::asio::async_write(*socket, *write_buffer, [listener, websocket, socket, header, write_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
                            if (!ec) {
                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Connected: Sent Handshake bytes " << bytes_transferred);
                                if (listener->onConnection) {
                                    listener->onConnection(websocket, header);
                                }
                                ReadHeader(listener, websocket, socket);
                            }
                            else {
                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket receivehandshake failed " << ec.message());
                            }
                        });
                    }
                    else {
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "WebSocket Generate_Handshake failed ");
                    }
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake failed " << ec.message());
                }
            });

        }
        void async_handshake(std::shared_ptr<WSListenerImpl> listener, std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
            read_handshake(listener, socket);
        }
        void async_handshake(std::shared_ptr<WSListenerImpl> listener, std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket) {

            socket->async_handshake(boost::asio::ssl::stream_base::server, [listener, socket](const boost::system::error_code& ec) {

                if (!ec) {
                    read_handshake(listener, socket);
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "async_handshake failed " << ec.message());
                }
            });

        }

        template<typename SOCKETCREATOR>void Listen(std::shared_ptr<WSListenerImpl> listener, SOCKETCREATOR&& socketcreator) {

            auto socket = socketcreator(listener);
            listener->acceptor.async_accept(socket->lowest_layer(), [listener, socket, socketcreator](const boost::system::error_code& ec)
            {
                if (!ec)
                {
                    async_handshake(listener, socket);
                }
                Listen(listener, socketcreator);
            });
        }
        WSListener CreateListener(unsigned short port)
        {
            WSListener tmp;
            tmp.WSListenerImpl_ = std::make_shared<WSListenerImpl>(port);
            return tmp;
        }

        WSListener CreateListener(
            unsigned short port,
            std::string Password,
            std::string Privatekey_File,
            std::string Publiccertificate_File,
            std::string dh_File)
        {

            WSListener tmp;
            tmp.WSListenerImpl_ = std::make_shared<WSListenerImpl>(port, Password, Privatekey_File, Publiccertificate_File, dh_File);
            return tmp;
        }
        void WSListener::startlistening()
        {
            if (WSListenerImpl_->sslcontext) {
                auto createsocket = [](auto c) {
                    return std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(c->io_service, *c->sslcontext);
                };
                Listen(WSListenerImpl_, createsocket);
            }
            else {
                auto createsocket = [](auto c) {
                    return std::make_shared<boost::asio::ip::tcp::socket>(c->io_service);
                };
                Listen(WSListenerImpl_, createsocket);
            }
        }
        void WSListener::onConnection(std::function<void(WSocket, const std::unordered_map<std::string, std::string>&)>& handle) {
            WSListenerImpl_->onConnection = handle;
        }
        void WSListener::onConnection(const std::function<void(WSocket, const std::unordered_map<std::string, std::string>&)>& handle) {
            WSListenerImpl_->onConnection = handle;
        }
        void WSListener::onMessage(std::function<void(WSocket, WSReceiveMessage&)>& handle) {
            WSListenerImpl_->onMessage = handle;
        }
        void WSListener::onMessage(const std::function<void(WSocket, WSReceiveMessage&)>& handle) {
            WSListenerImpl_->onMessage = handle;
        }
        void WSListener::onDisconnection(std::function<void(WSocket, WSReceiveMessage&)>& handle) {
            WSListenerImpl_->onDisconnection = handle;
        }
        void WSListener::onDisconnection(const std::function<void(WSocket, WSReceiveMessage&)>& handle) {
            WSListenerImpl_->onDisconnection = handle;
        }
        void WSListener::onPing(std::function<void(WSocket, const char *, size_t)>& handle) {
            WSListenerImpl_->onPing = handle;
        }
        void WSListener::onPing(const std::function<void(WSocket, const char *, size_t)>& handle) {
            WSListenerImpl_->onPing = handle;
        }
        void WSListener::onPong(std::function<void(WSocket, const char *, size_t)>& handle) {
            WSListenerImpl_->onPong = handle;
        }
        void WSListener::onPong(const std::function<void(WSocket, const char *, size_t)>& handle) {
            WSListenerImpl_->onPong = handle;
        }
        void WSListener::onHttpUpgrade(std::function<void(WSocket)>& handle) {
            WSListenerImpl_->onHttpUpgrade = handle;
        }
        void WSListener::onHttpUpgrade(const std::function<void(WSocket)>& handle) {
            WSListenerImpl_->onHttpUpgrade = handle;
        }
        void WSListener::set_ReadTimeout(unsigned int seconds) {
            WSListenerImpl_->ReadTimeout = seconds;
        }
        unsigned int WSListener::get_ReadTimeout() {
            return  WSListenerImpl_->ReadTimeout;
        }
        void WSListener::set_WriteTimeout(unsigned int seconds) {
            WSListenerImpl_->WriteTimeout = seconds;
        }
        unsigned int WSListener::get_WriteTimeout() {
            return  WSListenerImpl_->WriteTimeout;
        }
        void WSListener::set_MaxPayload(unsigned long long int bytes) {
            WSListenerImpl_->MaxPayload = bytes;
        }
        unsigned long long int WSListener::get_MaxPayload() {
            return  WSListenerImpl_->MaxPayload;
        }

        void WSListener::send(WSocket& s, WSSendMessage& msg) {
            if (s.WSocketImpl_->Socket) {
                SL::WS_LITE::send(WSListenerImpl_, s, s.WSocketImpl_->Socket, msg);
            }
            else {
                SL::WS_LITE::send(WSListenerImpl_, s, s.WSocketImpl_->TLSSocket, msg);
            }
        }
    }
}
