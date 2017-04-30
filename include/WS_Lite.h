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
            char* data;
            unsigned long long int  len;
            OpCode code;
            //compress the outgoing message?
            bool Compress;
        };


        //forward declares
        struct WSocketImpl;
        struct WSocket {
            std::shared_ptr<WSocketImpl> WSocketImpl_;

            bool is_open();
            std::string get_address();
            unsigned short get_port();
            bool is_v4();
            bool is_v6();
            bool is_loopback();
        };
        class WSListenerImpl;
        struct WSListener {
            std::shared_ptr<WSListenerImpl> WSListenerImpl_;

            void onConnection(std::function<void(WSocket, const std::unordered_map<std::string, std::string>&)>& handle);
            void onConnection(const std::function<void(WSocket, const std::unordered_map<std::string, std::string>&)>& handle);
         
            void onMessage(std::function<void(WSocket, WSReceiveMessage&)>& handle);
            void onMessage(const std::function<void(WSocket, WSReceiveMessage&)>& handle);

            void onDisconnection(std::function<void(WSocket, WSReceiveMessage&)>& handle);
            void onDisconnection(const std::function<void(WSocket, WSReceiveMessage&)>& handle);

            void onPing(std::function<void(WSocket, const char *, size_t)>& handle);
            void onPing(const std::function<void(WSocket, const char *, size_t)>& handle);

            void onPong(std::function<void(WSocket, const char *, size_t)>& handle);
            void onPong(const std::function<void(WSocket, const char *, size_t)>& handle);

            void onHttpUpgrade(std::function<void(WSocket)>& handle);
            void onHttpUpgrade(const std::function<void(WSocket)>& handle);

            void set_MaxPayload(unsigned long long int bytes);
            unsigned long long int get_MaxPayload();

            void set_ReadTimeout(unsigned int seconds);
            unsigned int  get_ReadTimeout();

            void set_WriteTimeout( unsigned int seconds);
            unsigned int  get_WriteTimeout();

            void send(WSocket& s, WSSendMessage& msg);

            void startlistening();
        };
        struct WSClientImpl;
        struct WSClient {
            std::shared_ptr<WSClientImpl> WSClientImpl_;

            void onConnection(std::function<void(WSocket, const std::unordered_map<std::string, std::string>&)>& handle);
            void onConnection(const std::function<void(WSocket, const std::unordered_map<std::string, std::string>&)>& handle);

            void onMessage(std::function<void(WSocket, WSReceiveMessage&)>& handle);
            void onMessage(const std::function<void(WSocket, WSReceiveMessage&)>& handle);

            void onDisconnection(std::function<void(WSocket, WSReceiveMessage&)>& handle);
            void onDisconnection(const std::function<void(WSocket, WSReceiveMessage&)>& handle);

            void onPing(std::function<void(WSocket, const char *, size_t)>& handle);
            void onPing(const std::function<void(WSocket, const char *, size_t)>& handle);

            void onPong(std::function<void(WSocket, const char *, size_t)>& handle);
            void onPong(const std::function<void(WSocket, const char *, size_t)>& handle);

            void onHttpUpgrade(std::function<void(WSocket)>& handle);
            void onHttpUpgrade(const std::function<void(WSocket)>& handle);

            void set_MaxPayload(unsigned long long int bytes);
            unsigned long long int get_MaxPayload();

            void set_ReadTimeout(unsigned int seconds);
            unsigned int  get_ReadTimeout();

            void set_WriteTimeout(unsigned int seconds);
            unsigned int  get_WriteTimeout();

            void send(WSocket& s, WSSendMessage& msg);

            void connect(const char* host, unsigned short port);
        };
        
        WSListener CreateListener(unsigned short port);
        WSListener CreateListener(
            unsigned short port,
            std::string Password,
            std::string Privatekey_File,
            std::string Publiccertificate_File,
            std::string dh_File);

        WSClient CreateClient(std::string Publiccertificate_File);
        WSClient CreateClient();

    }
}

