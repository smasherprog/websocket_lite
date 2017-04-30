#include "WS_Lite.h"
#include "Logging.h"
#include "internal/WebSocketProtocol.h"

#include <fstream>
#include <string>

namespace SL {
    namespace WS_LITE {

        std::ifstream::pos_type filesize(const std::string& filename)
        {
            std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
            return in.tellg();
        }

        class WSClient : public WSContext {
        public:


            WSClient(std::string Publiccertificate_File)
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

            WSClient()
            {
            }

            ~WSClient() {

            }



        };

        template <class SOCKETTYPE>void ReadBody(std::shared_ptr<WSClient> clienthub, std::shared_ptr<WSocket> websocket, SOCKETTYPE socket, std::shared_ptr<WSHeader> header) {

            readexpire_from_now(websocket, clienthub->ReadTimeout);
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
            if (size > clienthub->MaxPayload) {
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Payload exceeded MaxPayload size ");
                return;
            }

            boost::asio::async_read(*socket, boost::asio::buffer(buffer.get(), static_cast<size_t>(size)), [clienthub, websocket, socket, header, buffer, size](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    if (size != bytes_transferred) {
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "size != bytes_transferred");
                        return;
                    }
                    else if (header->Opcode == OpCode::PING) {
                        if (clienthub->onPing) {
                            clienthub->onPing(websocket, buffer.get(), static_cast<size_t>(size));
                        }
                        auto unpacked = UnpackedMessage{ buffer.get(), size , OpCode::PONG };
                        send(*websocket, unpacked);
                    }
                    else if (header->Opcode == OpCode::PONG) {
                        if (clienthub->onPong) {
                            clienthub->onPong(websocket, buffer.get(), static_cast<size_t>(size));
                        }
                    }
                    else if (clienthub->onMessage) {
                        auto unpacked = UnpackedMessage{ buffer.get(), size , header->Opcode };
                        auto packed = PackgedMessageInfo{ size };
                        clienthub->onMessage(websocket, unpacked, packed);
                    }
                    ReadHeader(clienthub, websocket, socket);
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadBody " << ec.message());
                }
            });
        }
        template <class SOCKETTYPE>void ReadHeader(std::shared_ptr<WSClient> clienthub, std::shared_ptr<WSocket> websocket, SOCKETTYPE socket) {
            readexpire_from_now(websocket, 0);
            auto buff = std::make_shared<WSHeader>();
            boost::asio::async_read(*socket, boost::asio::buffer(buff.get(), 2), [clienthub, websocket, socket, buff](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    assert(bytes_transferred == 2);
                    if (buff->Mask) {//Close connection if the server sends a masked message
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Closing connection because mask was received from a server");
                    }
                    else {
                        auto readbytes = GetPayloadBytes(buff.get());
                        if (readbytes > 1) {
                            boost::asio::async_read(*socket, boost::asio::buffer(&buff->ExtendedPayloadlen, readbytes), [clienthub, websocket, socket, buff, readbytes](const boost::system::error_code& ec, size_t bytes_transferred) {
                                if (readbytes != bytes_transferred) {
                                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "readbytes != bytes_transferred ");
                                }
                                else if (!ec) {
                                    ReadBody(clienthub, websocket, socket, buff);
                                }
                                else {
                                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "readheader ExtendedPayloadlen " << ec.message());
                                }
                            });
                        }
                        else {
                            ReadBody(clienthub, websocket, socket, buff);
                        }
                    }
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "ReadHeader Failed: " << ec.message());
                }
            });
        }
        bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx)
        {
            char subject_name[256];
            X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
            X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Verifying " << subject_name);

            return preverified;
        }
        template<class SOCKETTYPE>void ConnectHandshake(std::shared_ptr<WSClient> self, SOCKETTYPE& socket) {


            auto write_buffer(std::make_shared<boost::asio::streambuf>());
            std::ostream request(write_buffer.get());
            auto accept_sha1 = Generate_Handshake(get_address(*socket), request);

            boost::asio::async_write(*socket, *write_buffer, [write_buffer, accept_sha1, socket, self](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Sent Handshake bytes " << bytes_transferred);
                    auto read_buffer(std::make_shared<boost::asio::streambuf>());
                    boost::asio::async_read_until(*socket, *read_buffer, "\r\n\r\n", [read_buffer, accept_sha1, socket, self](const boost::system::error_code& ec, size_t bytes_transferred) {
                        if (!ec) {
                            SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Read Handshake bytes " << bytes_transferred);
                            std::istream stream(read_buffer.get());
                            auto header = Parse_Handshake("1.1", stream);
                            if (cppcodec::base64_rfc4648::decode<std::string>(header[HTTP_SECWEBSOCKETACCEPT]) == accept_sha1) {
                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Connected ");
                                auto websocket = std::make_shared<WSocket>(self->io_service);
                                set_Socket(websocket, socket);
                                if (self->onHttpUpgrade) {
                                    self->onHttpUpgrade(websocket);
                                }
                                if (self->onConnection) {
                                    self->onConnection(websocket, header);
                                }
                                if (read_buffer->size() > bytes_transferred) {
                                    //check and handle case where more data is read
                                }
                                ReadHeader(self, websocket, socket);
                            }
                            else {
                                auto msg = "WebSocket handshake failed " + ec.message();
                                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, msg);
                                if (self->onDisconnection) {
                                    std::weak_ptr<WSocket> ptr;
                                    self->onDisconnection(ptr, 0, msg.c_str(), msg.size());
                                }
                            }
                        }
                    });
                }
                else {
                    auto msg = "Failed sending handshake " + ec.message();
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, msg);
                    if (self->onDisconnection) {
                        std::weak_ptr<WSocket> ptr;
                        self->onDisconnection(ptr, 0, msg.c_str(), msg.size());
                    }
                }
            });

        }
        void async_handshake(std::shared_ptr<WSClient> self, std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
            ConnectHandshake(self, socket);
        }
        void async_handshake(std::shared_ptr<WSClient> self, std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket) {
            socket->async_handshake(boost::asio::ssl::stream_base::client, [socket, self](const boost::system::error_code& ec) {
                if (!ec)
                {
                    ConnectHandshake(self, socket);
                }
                else {
                    auto msg = "Failed async_handshake " + ec.message();
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, msg);
                    if (self->onDisconnection) {
                        std::weak_ptr<WSocket> ptr;
                        auto b = WSReceiveMessage{ msg.c_str(), msg.size(), OpCode::TEXT };
                        self->onDisconnection(ptr, b);
                    }
                }
            });

        }
        template<typename SOCKETCREATOR>void Connect(std::shared_ptr<WSClient> self, const char* host, unsigned short port, SOCKETCREATOR&& socketcreator) {

            auto socket = socketcreator(self);
            boost::asio::ip::tcp::resolver resolver(self->io_service);
            auto portstr = std::to_string(port);
            boost::asio::ip::tcp::resolver::query query(host, portstr.c_str());
            boost::system::error_code ec;
            auto endpoint = resolver.resolve(query, ec);

            if (ec) {
                SL_WS_LITE_LOG(Logging_Levels::ERROR_log_level, "resolve " << ec.message());
            }
            else {
                boost::asio::async_connect(socket->lowest_layer(), endpoint, [socket, self](const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator)
                {
                    if (!ec)
                    {
                        async_handshake(self, socket);
                    }
                    else {
                        auto msg = "Failed async_connect " + ec.message();
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, msg);
                        if (self->onDisconnection) {
                            std::weak_ptr<WSocket> ptr;
                            self->onDisconnection(ptr, 0, msg.c_str(), msg.size());
                        }
                    }
                });
            }

        }


        std::shared_ptr<WSClient> CreateClient(std::string Publiccertificate_File) {
            return std::make_shared<WSClient>(Publiccertificate_File);
        }
        std::shared_ptr<WSClient> CreateClient() {
            return std::make_shared<WSClient>();
        }
        void Connect(std::shared_ptr<WSClient> client, const char* host, unsigned short port) {
            if (client) {
                if (client->sslcontext) {
                    auto createsocket = [](auto c) {
                        auto socket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(c->io_service, *c->sslcontext);
                        socket->set_verify_mode(boost::asio::ssl::verify_peer);
                        socket->set_verify_callback(std::bind(&verify_certificate, std::placeholders::_1, std::placeholders::_2));
                        return socket;

                    };
                    Connect(client, host, port, createsocket);
                }
                else {
                    auto createsocket = [](auto c) {
                        return std::make_shared<boost::asio::ip::tcp::socket>(c->io_service);
                    };
                    Connect(client, host, port, createsocket);
                }

            }
        }

        void onConnection(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle) {
            if (l) {
                l->onConnection = handle;
            }
        }
        void onConnection(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, const std::unordered_map<std::string, std::string>&)>& handle) {
            if (l) {
                l->onConnection = handle;
            }
        }
        void onMessage(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, WSReceiveMessage&)>& handle) {
            if (l) {
                l->onMessage = handle;
            }
        }
        void onMessage(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, WSReceiveMessage&)>& handle) {
            if (l) {
                l->onMessage = handle;
            }
        }

        void onDisconnection(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, WSReceiveMessage&)>& handle) {
            if (l) {
                l->onDisconnection = handle;
            }
        }
        void onDisconnection(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, WSReceiveMessage&)>& handle) {
            if (l) {
                l->onDisconnection = handle;
            }
        }

        void onPing(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
            if (l) {
                l->onPing = handle;
            }
        }
        void onPing(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
            if (l) {
                l->onPing = handle;
            }
        }

        void onPong(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
            if (l) {
                l->onPong = handle;
            }
        }
        void onPong(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>, char *, size_t)>& handle) {
            if (l) {
                l->onPong = handle;
            }
        }

        void onHttpUpgrade(std::shared_ptr<WSClient> l, std::function<void(std::weak_ptr<WSocket>)>& handle) {
            if (l) {
                l->onHttpUpgrade = handle;
            }
        }
        void onHttpUpgrade(std::shared_ptr<WSClient> l, const std::function<void(std::weak_ptr<WSocket>)>& handle) {
            if (l) {
                l->onHttpUpgrade = handle;
            }
        }

        void set_ReadTimeout(WSClient& s, unsigned int seconds) {
            s.ReadTimeout = seconds;
        }

        unsigned int get_ReadTimeout(WSClient& s) {
            return s.ReadTimeout;
        }

        void set_WriteTimeout(WSClient& s, unsigned int seconds) {
            s.WriteTimeout = seconds;
        }

        unsigned int get_WriteTimeout(WSClient& s) {
            return s.WriteTimeout;
        }
        void set_MaxPayload(WSClient& s, unsigned long long int bytes) {
            s.MaxPayload = bytes;
        }
        unsigned long long int get_MaxPayload(WSClient& s) {
            return s.MaxPayload;
        }


        template<class SOCKETTYPE>void send(std::shared_ptr<WSClient>& l, WSocket& s, SOCKETTYPE& socket, WSSendMessage& msg) {

            WSHeader header;
            header.FIN = true;
            header.Mask = true;
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
            writeexpire_from_now(s, l->WriteTimeout);
            boost::system::error_code ec;
            auto bytes_written = boost::asio::write(socket, boost::asio::buffer(&header, sizeof(header)), ec);
            assert(bytes_written == sizeof(header));
            if (!ec)
            {
                ec.clear();

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

                bytes_written = boost::asio::write(socket, boost::asio::buffer(mask, sizeof(mask)), ec);
                if (!ec) {
                    bytes_written = boost::asio::write(socket, boost::asio::buffer(p, static_cast<size_t>(msg.len)), ec);
                    if (ec) {
                        SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "write payload failed " << ec.message());
                    }
                }
                else {
                    SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "write mask failed " << ec.message());
                }
            }
            else {
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "write header failed " << ec.message());
            }
        }
        void send(std::shared_ptr<WSClient>& l, WSocket& s, WSReceiveMessage& msg) {
            if (s.Socket) {
                send(l, s, s.Socket, msg);
            }
            else {
                send(l, s, s.TLSSocket, msg);
            }
        }
        bool WSocket::is_open() {
            if (s.Socket) {
                return s.Socket->is_open();
            }
            else {
                return s.TLSSocket->lowest_layer().is_open();
            }
        }
        std::string WSocket::get_address() {
            if (s.Socket) {
                return get_address(*s.Socket);
            }
            else {
                return get_address(*s.TLSSocket);
            }
        }
        unsigned short WSocket::get_port() {
            if (s.Socket) {
                return get_port(*s.Socket);
            }
            else {
                return get_port(*s.TLSSocket);
            }
        }
        bool WSocket::is_v4() {

            if (s.Socket) {
                return is_v4(*s.Socket);
            }
            else {
                return is_v4(*s.TLSSocket);
            }
        }
        bool WSocket::is_v6() {

            if (s.Socket) {
                return is_v6(*s.Socket);
            }
            else {
                return is_v6(*s.TLSSocket);
            }
        }
        bool WSocket::is_loopback() {
           
            if (Socket) {
                return is_loopback(Socket);
            }
            else {
                return is_loopback(*s.TLSSocket);
            }
        }
    }
}
