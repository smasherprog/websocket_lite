#include "WS_Lite.h"
#include "Logging.h"
#include "internal/WebSocketProtocol.h"

namespace SL {
    namespace WS_LITE {


        class WSListener : public WSContext {
        public:

            boost::asio::ip::tcp::acceptor acceptor;

            WSListener(unsigned short port,
                std::string Password,
                std::string Privatekey_File,
                std::string Publiccertificate_File,
                std::string dh_File) :
                WSListener(port)
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

            WSListener(unsigned short port) :acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) { }

            ~WSListener() {
                boost::system::error_code ec;
                acceptor.close(ec);
            }
        };

        template <class SOCKETTYPE>void ReadBody(std::shared_ptr<WSListener> listener, std::shared_ptr<WSocket> websocket, SOCKETTYPE socket, std::shared_ptr<WSHeader> header) {

            readexpire_from_now(websocket, listener->ReadTimeout);
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
                        auto unpacked = UnpackedMessage{ buffer.get() + 4, size - 4, OpCode::PONG };
                        send(*websocket, unpacked);
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
                        auto unpacked = UnpackedMessage{ p, size - 4, header->Opcode };
                        auto packed = PackgedMessageInfo{ size - 4 };
                        listener->onMessage(websocket, unpacked, packed);
                    }
                    ReadHeader(listener, websocket, socket);
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadBody " << ec.message());
                }
            });
        }
        template <class SOCKETTYPE>void ReadHeader(std::shared_ptr<WSListener> listener, std::shared_ptr<WSocket> websocket, SOCKETTYPE socket) {
            readexpire_from_now(websocket, 0);
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
        template<class SOCKETTYPE>void read_handshake(std::shared_ptr<WSListener> listener, SOCKETTYPE& socket) {
            auto read_buffer(std::make_shared<boost::asio::streambuf>());
            boost::asio::async_read_until(*socket, *read_buffer, "\r\n\r\n", [listener, socket, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);

                    std::istream stream(read_buffer.get());
                    auto header = Parse_Handshake("1.1", stream);

                    auto write_buffer(std::make_shared<boost::asio::streambuf>());
                    std::ostream handshake(write_buffer.get());
                    if (Generate_Handshake(header, handshake)) {
                        auto websocket = std::make_shared<WSocket>(listener->io_service);
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
        void async_handshake(std::shared_ptr<WSListener> listener, std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
            read_handshake(listener, socket);
        }
        void async_handshake(std::shared_ptr<WSListener> listener, std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket) {

            socket->async_handshake(boost::asio::ssl::stream_base::server, [listener, socket](const boost::system::error_code& ec) {

                if (!ec) {
                    read_handshake(listener, socket);
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "async_handshake failed " << ec.message());
                }
            });

        }

        template<typename SOCKETCREATOR>void Listen(std::shared_ptr<WSListener> listener, SOCKETCREATOR&& socketcreator) {

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
        std::shared_ptr<WSListener> CreateListener(unsigned short port)
        {
            return std::make_shared<WSListener>(port);
        }

        std::shared_ptr<WSListener> CreateListener(
            unsigned short port,
            std::string Password,
            std::string Privatekey_File,
            std::string Publiccertificate_File,
            std::string dh_File)
        {
            return std::make_shared<WSListener>(port, Password, Privatekey_File, Publiccertificate_File, dh_File);
        }
        void StartListening(std::shared_ptr<WSListener>& l)
        {
            if (l) {
                if (l->sslcontext) {
                    auto createsocket = [](auto c) {
                        return std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(c->io_service, *c->sslcontext);
                    };
                    Listen(l, createsocket);
                }
                else {
                    auto createsocket = [](auto c) {
                        return std::make_shared<boost::asio::ip::tcp::socket>(c->io_service);
                    };
                    Listen(l, createsocket);
                }
            }
        }
        void onConnection(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle) {
            if (l) {
                l->onConnection = handle;
            }
        }
        void onConnection(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle) {
            if (l) {
                l->onConnection = handle;
            }
        }
        void onMessage(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)>& handle) {
            if (l) {
                l->onMessage = handle;
            }
        }
        void onMessage(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, UnpackedMessage&, PackgedMessageInfo&)>& handle) {
            if (l) {
                l->onMessage = handle;
            }
        }

        void onDisconnection(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, int code, const char *message, size_t length)>& handle) {
            if (l) {
                l->onDisconnection = handle;
            }
        }
        void onDisconnection(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, int code, const char *message, size_t length)>& handle) {
            if (l) {
                l->onDisconnection = handle;
            }
        }

        void onPing(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, const char *, size_t)>& handle) {
            if (l) {
                l->onPing = handle;
            }
        }
        void onPing(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, const char *, size_t)>& handle) {
            if (l) {
                l->onPing = handle;
            }
        }

        void onPong(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>, const char *, size_t)>& handle) {
            if (l) {
                l->onPong = handle;
            }
        }
        void onPong(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>, const char *, size_t)>& handle) {
            if (l) {
                l->onPong = handle;
            }
        }

        void onHttpUpgrade(std::shared_ptr<WSListener> l, std::function<void(std::weak_ptr<WSocket>)>& handle) {
            if (l) {
                l->onHttpUpgrade = handle;
            }
        }
        void onHttpUpgrade(std::shared_ptr<WSListener> l, const std::function<void(std::weak_ptr<WSocket>)>& handle) {
            if (l) {
                l->onHttpUpgrade = handle;
            }
        }
        void send(const WSocket& s, const UnpackedMessage& msg) {

        }
        void set_ReadTimeout(WSListener& s, unsigned int seconds) {
            s.ReadTimeout = seconds;
        }

        unsigned int get_ReadTimeout(WSListener& s) {
            return s.ReadTimeout;
        }

        void set_WriteTimeout(WSListener& s, unsigned int seconds) {
            s.WriteTimeout = seconds;
        }

        unsigned int get_WriteTimeout(WSListener& s) {
            return s.WriteTimeout;
        }

        void set_MaxPayload(WSListener& s, unsigned long long int bytes) {
            s.MaxPayload = bytes;
        }
        unsigned long long int get_MaxPayload(WSListener& s) {
            return s.MaxPayload;
        }
    }
}
