#pragma once
#include <memory>
#include <string>
#include <functional>
#include <unordered_map>

namespace SL {
    namespace WS_LITE {

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

        const auto HTTP_ENDLINE = "\r\n";
        const auto HTTP_KEYVALUEDELIM = ": ";

        enum OpCode : unsigned char {
            CONTINUATION = 0,
            TEXT = 1,
            BINARY = 2,
            CLOSE = 8,
            PING = 9,
            PONG = 10
        };
        //this is the message after being uncompressed
        struct WSReceiveMessage {
            const char* data;
            unsigned long long int  len;
            OpCode code;
        };
        struct WSSendMessage {
            std::shared_ptr<char> Buffer;
            char* Data;
            unsigned long long int  len;
            OpCode code;
            //compress the outgoing message?
            bool Compress;
        };



        class WSListener;
        class WSClient;
        struct WSocketImpl;
        class WSocket {
            std::shared_ptr<WSocketImpl> WSocketImpl_;
        public:
            WSocket(const std::shared_ptr<WSocketImpl>& ptr) : WSocketImpl_(ptr) {}
            //can be used to compare two WSocket objects
            bool operator=(const WSocket& s) { return s.WSocketImpl_ == WSocketImpl_; }
            bool is_open();
            std::string get_address();
            unsigned short get_port();
            bool is_v4();
            bool is_v6();
            bool is_loopback();
            friend WSListener;
            friend WSClient;
        };
        class WSListenerImpl;
        class WSListener {
            std::shared_ptr<WSListenerImpl> Impl_;
        public:
            //when a connection is fully established. If onconnect is called, then a matching onDisconnection is guaranteed
            void onConnection(std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle);
            //when a connection is fully established.  If onconnect is called, then a matching onDisconnection is guaranteed
            void onConnection(const std::function<void(WSocket&, const std::unordered_map<std::string, std::string>&)>& handle);
            //when a message has been received
            void onMessage(std::function<void(WSocket&, WSReceiveMessage&)>& handle);
            //when a message has been received
            void onMessage(const std::function<void(WSocket&, WSReceiveMessage&)>& handle);
            //when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
            void onDisconnection(std::function<void(WSocket&, WSReceiveMessage&)>& handle);
            //when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
            void onDisconnection(const std::function<void(WSocket&, WSReceiveMessage&)>& handle);
            //when a ping is received from a client
            void onPing(std::function<void(WSocket&, const char *, size_t)>& handle);            
            //when a ping is received from a client
            void onPing(const std::function<void(WSocket&, const char *, size_t)>& handle);
            //when a pong is received from a client
            void onPong(std::function<void(WSocket&, const char *, size_t)>& handle);
            //when a pong is received from a client
            void onPong(const std::function<void(WSocket&, const char *, size_t)>& handle);
            //before onconnection is called, the conection is upgraded
            void onHttpUpgrade(std::function<void(WSocket&)>& handle);
            //before onconnection is called, the conection is upgraded
            void onHttpUpgrade(const std::function<void(WSocket&)>& handle);
            //the maximum payload size
            void set_MaxPayload(unsigned long long int bytes);
            //the maximum payload size
            unsigned long long int get_MaxPayload();
            //maximum time in seconds before a client is considered disconnected -- for reads
            void set_ReadTimeout(unsigned int seconds);
            //get the current read timeout in seconds
            unsigned int  get_ReadTimeout();
            //maximum time in seconds before a client is considered disconnected -- for writes
            void set_WriteTimeout( unsigned int seconds);
            //get the current write timeout in seconds
            unsigned int  get_WriteTimeout();
            //send a message to a specific client
            void send(WSocket& s, WSSendMessage& msg);
            //start the process to listen for clients. This is non-blocking and will return immediatly
            void startlistening();
            //factory to create listeners. Use this if you ARE NOT using TLS
            static WSListener CreateListener(unsigned short port);
            //factory to create listeners. Use this if you ARE using TLS
            static WSListener CreateListener(
                unsigned short port,
                std::string Password,
                std::string Privatekey_File,
                std::string Publiccertificate_File,
                std::string dh_File);
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
            void onMessage(std::function<void(WSocket&, WSReceiveMessage&)>& handle);
            //when a message has been received
            void onMessage(const std::function<void(WSocket&, WSReceiveMessage&)>& handle);
            //when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
            void onDisconnection(std::function<void(WSocket&, WSReceiveMessage&)>& handle);
            //when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
            void onDisconnection(const std::function<void(WSocket&, WSReceiveMessage&)>& handle);
            //when a ping is received from a client
            void onPing(std::function<void(WSocket&, const char *, size_t)>& handle);
            //when a ping is received from a client
            void onPing(const std::function<void(WSocket&, const char *, size_t)>& handle);
            //when a pong is received from a client
            void onPong(std::function<void(WSocket&, const char *, size_t)>& handle);
            //when a pong is received from a client
            void onPong(const std::function<void(WSocket&, const char *, size_t)>& handle);
            //before onconnection is called, the conection is upgraded
            void onHttpUpgrade(std::function<void(WSocket&)>& handle);
            //before onconnection is called, the conection is upgraded
            void onHttpUpgrade(const std::function<void(WSocket&)>& handle);
            //the maximum payload size
            void set_MaxPayload(unsigned long long int bytes);
            //the maximum payload size
            unsigned long long int get_MaxPayload();
            //maximum time in seconds before a client is considered disconnected -- for reads
            void set_ReadTimeout(unsigned int seconds);
            //get the current read timeout in seconds
            unsigned int  get_ReadTimeout();
            //maximum time in seconds before a client is considered disconnected -- for writes
            void set_WriteTimeout(unsigned int seconds);
            //get the current write timeout in seconds
            unsigned int  get_WriteTimeout();
            //send a message to a specific client
            void send(WSocket& s, WSSendMessage& msg);
            //connect to an endpoint. This is non-blocking and will return immediatly. If the library is unable to establish a connection, ondisconnection will be called. 
            void connect(const char* host, unsigned short port);
            //factory to create clients. Use this if you ARE NOT using TLS
            static WSClient CreateClient();           
            //factory to create clients. Use this if you ARE using TLS
            static WSClient CreateClient(std::string Publiccertificate_File);
        };
    }
}

