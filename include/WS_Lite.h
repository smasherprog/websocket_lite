#pragma once
#include <memory>
#include <string>
#include <functional>
#include <unordered_map>
#include <chrono>

namespace SL {
    namespace WS_LITE {
        template <typename T, typename Meaning>
        struct Explicit
        {
            Explicit() { }
            Explicit(T value) : value(value) { }
            inline operator T () const { return value; }
            T value;
        };
        namespace INTERNAL {
            struct PorNumbertTag { };
            struct ThreadCountTag { };
        }

        typedef Explicit<unsigned short, INTERNAL::PorNumbertTag> PortNumber;
        typedef Explicit<unsigned short, INTERNAL::ThreadCountTag> ThreadCount;

        const auto HTTP_METHOD = "Method";
        const auto HTTP_PATH = "Path";
        const auto HTTP_HOST = "Host";
        const auto HTTP_VERSION = "Http_Version";
        const auto HTTP_STATUSCODE = "Http_StatusCode";
        const auto HTTP_CONTENTLENGTH = "Content-Length";
        const auto HTTP_CONTENTTYPE = "Content-Type";
        const auto HTTP_CACHECONTROL = "Cache-Control";
        const auto HTTP_LASTMODIFIED = "Last-Modified";
        const auto HTTP_SECWEBSOCKETKEY = "Sec-WebSocket-Key";
        const auto HTTP_SECWEBSOCKETACCEPT = "Sec-WebSocket-Accept";
        const auto HTTP_SECWEBSOCKETEXTENSIONS = "Sec-WebSocket-Extensions";
        const auto PERMESSAGEDEFLATE = "permessage-deflate";

        const auto HTTP_ENDLINE = "\r\n";
        const auto HTTP_KEYVALUEDELIM = ": ";

        enum OpCode : unsigned char {
            CONTINUATION = 0,
            TEXT = 1,
            BINARY = 2,
            CLOSE = 8,
            PING = 9,
            PONG = 10,
            INVALID = 255
        };
        struct WSMessage {
            unsigned char *data;
            size_t len;
            OpCode code;
            //buffer is here to ensure the lifetime of the unsigned char *data in this structure
            //users should set the *data variable to be the beginning of the data to send. Then, set the Buffer shared ptr as well to make sure the lifetime of the data
            std::shared_ptr<unsigned char> Buffer;
        };

        class WSListener;
        class WSClient;
        struct WSocketImpl;
        class WSocket {
            std::shared_ptr<WSocketImpl> WSocketImpl_;
        public:
            WSocket(const std::shared_ptr<WSocketImpl>& s) :WSocketImpl_(s) {}
            //WSocket() {}
            //can be used to compare two WSocket objects
            bool operator=(const WSocket& s) { return s.WSocketImpl_ == WSocketImpl_; }
            bool is_open();
            std::string get_address();
            unsigned short get_port();
            bool is_v4();
            bool is_v6();
            bool is_loopback();
            operator bool() const { return WSocketImpl_.operator bool(); }
            friend WSListener;
            friend WSClient;
        };
        class WSContext;
        class WSListenerImpl;
        class WSListener {
            std::shared_ptr<WSListenerImpl> Impl_;
        public:
            //when a connection is fully established. If onconnect is called, then a matching onDisconnection is guaranteed
            void onConnection(std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle);
            //when a connection is fully established.  If onconnect is called, then a matching onDisconnection is guaranteed
            void onConnection(const std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle);
            //when a message has been received
            void onMessage(std::function<void(WSocket&, const WSMessage&)>& handle);
            //when a message has been received
            void onMessage(const std::function<void(WSocket&, const WSMessage&)>& handle);
            //when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
            void onDisconnection(std::function<void(WSocket&, unsigned short, const std::string&)>& handle);
            //when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
            void onDisconnection(const std::function<void(WSocket&, unsigned short, const std::string&)>& handle);
            //when a ping is received from a client
            void onPing(std::function<void(WSocket&, const unsigned char *, size_t)>& handle);
            //when a ping is received from a client
            void onPing(const std::function<void(WSocket&, const unsigned char *, size_t)>& handle);
            //when a pong is received from a client
            void onPong(std::function<void(WSocket&, const unsigned char *, size_t)>& handle);
            //when a pong is received from a client
            void onPong(const std::function<void(WSocket&, const unsigned char *, size_t)>& handle);
            //before onconnection is called, the conection is upgraded
            void onHttpUpgrade(std::function<void(WSocket&)>& handle);
            //before onconnection is called, the conection is upgraded
            void onHttpUpgrade(const std::function<void(WSocket&)>& handle);
            //the maximum payload size
            void set_MaxPayload(size_t bytes);
            //the maximum payload size
            unsigned long long int get_MaxPayload();
            //maximum time in seconds before a client is considered disconnected -- for reads
            void set_ReadTimeout(std::chrono::seconds seconds);
            //get the current read timeout in seconds
            std::chrono::seconds get_ReadTimeout();
            //maximum time in seconds before a client is considered disconnected -- for writes
            void set_WriteTimeout(std::chrono::seconds seconds);
            //get the current write timeout in seconds
            std::chrono::seconds get_WriteTimeout();
            //send a message to a specific client
            void send(const WSocket& s, WSMessage& msg, bool compressmessage);
            //send a close message and close the socket
            void close(const WSocket& s, unsigned short code = 1000, const std::string& msg = "");
            //start the process to listen for clients. This is non-blocking and will return immediatly
            void startlistening();
            friend WSContext;
        };
        class WSClientImpl;
        class WSClient {
            std::shared_ptr<WSClientImpl> Impl_;
        public:
            //when a connection is fully established. If onconnect is called, then a matching onDisconnection is guaranteed
            void onConnection(std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle);
            //when a connection is fully established.  If onconnect is called, then a matching onDisconnection is guaranteed
            void onConnection(const std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle);
            //when a message has been received
            void onMessage(std::function<void(WSocket&, const WSMessage&)>& handle);
            //when a message has been received
            void onMessage(const std::function<void(WSocket&, const WSMessage&)>& handle);
            //when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
            void onDisconnection(std::function<void(WSocket&, unsigned short, const std::string&)>& handle);
            //when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
            void onDisconnection(const std::function<void(WSocket&, unsigned short, const std::string&)>& handle);
            //when a ping is received from a client
            void onPing(std::function<void(WSocket&, const unsigned char *, size_t)>& handle);
            //when a ping is received from a client
            void onPing(const std::function<void(WSocket&, const unsigned char *, size_t)>& handle);
            //when a pong is received from a client
            void onPong(std::function<void(WSocket&, const unsigned char *, size_t)>& handle);
            //when a pong is received from a client
            void onPong(const std::function<void(WSocket&, const unsigned char *, size_t)>& handle);
            //before onconnection is called, the conection is upgraded
            void onHttpUpgrade(std::function<void(WSocket&)>& handle);
            //before onconnection is called, the conection is upgraded
            void onHttpUpgrade(const std::function<void(WSocket&)>& handle);
            //the maximum payload size
            void set_MaxPayload(size_t bytes);
            //the maximum payload size
            unsigned long long int get_MaxPayload();
            //maximum time in seconds before a client is considered disconnected -- for reads
            void set_ReadTimeout(std::chrono::seconds seconds);
            //get the current read timeout in seconds
            std::chrono::seconds get_ReadTimeout();
            //maximum time in seconds before a client is considered disconnected -- for writes
            void set_WriteTimeout(std::chrono::seconds seconds);
            //get the current write timeout in seconds
            std::chrono::seconds get_WriteTimeout();
            //send a message to a specific client
            void send(const WSocket& s, WSMessage& msg, bool compressmessage);
            //send a close message and close the socket
            void close(const WSocket& s, unsigned short code = 1000, const std::string& msg = "");
            //connect to an endpoint. This is non-blocking and will return immediatly. If the library is unable to establish a connection, ondisconnection will be called. 
            void connect(const char* host, PortNumber port);
            friend WSContext;
        };
        class WSContextImpl;
        class WSContext {
            std::shared_ptr<WSContextImpl> Impl_;
        public:
            WSContext(ThreadCount threadcount);

            //Use this if you ARE NOT using TLS
            WSListener CreateListener(PortNumber port);
            //Use this if you ARE using TLS
            WSListener CreateListener(
                PortNumber port,
                std::string Password,
                std::string Privatekey_File,
                std::string Publiccertificate_File,
                std::string dh_File);
            //factory to create clients. Use this if you ARE NOT using TLS
            WSClient CreateClient();
            //factory to create clients. Use this if you ARE using TLS
            WSClient CreateClient(std::string Publiccertificate_File);

        };
    }
}

