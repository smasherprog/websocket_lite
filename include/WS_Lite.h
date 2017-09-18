#pragma once
#include "TLSContext.h"
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
typedef struct x509_store_ctx_st X509_STORE_CTX;

#if defined(WINDOWS) || defined(WIN32)
#if defined(WS_LITE_DLL)
#define WS_LITE_EXTERN __declspec(dllexport)
#define WS_EXPIMP_TEMPLATE
#else
#define WS_LITE_EXTERN
#define WS_EXPIMP_TEMPLATE extern
#endif
#else
#define WS_LITE_EXTERN
#define WS_EXPIMP_TEMPLATE
#endif

namespace SL {
namespace WS_LITE {
    template <typename T, typename Meaning> struct Explicit {
        Explicit() {}
        Explicit(T value) : value(value) {}
        inline operator T() const { return value; }
        T value;
    };
    namespace INTERNAL {
        struct PorNumbertTag {
        };
        struct ThreadCountTag {
        };
    } // namespace INTERNAL

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

    enum OpCode : unsigned char { CONTINUATION = 0, TEXT = 1, BINARY = 2, CLOSE = 8, PING = 9, PONG = 10, INVALID = 255 };
    enum SocketStatus : int { CONNECTING, CONNECTED, CLOSING, CLOSED };
    enum ExtensionOptions : unsigned char { NO_OPTIONS = 0, DEFLATE = 1, NO_CONTEXT_TAKEOVER = 2 };
    struct WSMessage {
        unsigned char *data;
        size_t len;
        OpCode code;
        // buffer is here to ensure the lifetime of the unsigned char *data in this structure
        // users should set the *data variable to be the beginning of the data to send. Then, set the Buffer shared ptr as well to make sure the
        // lifetime of the data
        std::shared_ptr<unsigned char> Buffer;
    };

    class IWSocket : public std::enable_shared_from_this<IWSocket> {
      public:
        virtual ~IWSocket() {}
        virtual SocketStatus is_open() const = 0;
        virtual std::string get_address() const = 0;
        virtual unsigned short get_port() const = 0;
        virtual bool is_v4() const = 0;
        virtual bool is_v6() const = 0;
        virtual bool is_loopback() const = 0;
        virtual void send(const WSMessage &msg, bool compressmessage) = 0;
        // send a close message and close the socket
        virtual void close(unsigned short code = 1000, const std::string &msg = "") = 0;
    };
    class WS_LITE_EXTERN IWSHub {
      public:
        virtual ~IWSHub() {}
        // the maximum payload size
        virtual void set_MaxPayload(size_t bytes) = 0;
        // the maximum payload size
        virtual size_t get_MaxPayload() = 0;
        // maximum time in seconds before a client is considered disconnected -- for reads
        virtual void set_ReadTimeout(std::chrono::seconds seconds) = 0;
        // get the current read timeout in seconds
        virtual std::chrono::seconds get_ReadTimeout() = 0;
        // maximum time in seconds before a client is considered disconnected -- for writes
        virtual void set_WriteTimeout(std::chrono::seconds seconds) = 0;
        // get the current write timeout in seconds
        virtual std::chrono::seconds get_WriteTimeout() = 0;
    };
    class WS_LITE_EXTERN IWSListener_Configuration {
      public:
        virtual ~IWSListener_Configuration() {}

        // when a connection is fully established.  If onconnect is called, then a matching onDisconnection is guaranteed
        virtual std::shared_ptr<IWSListener_Configuration>
        onConnection(const std::function<void(const std::shared_ptr<IWSocket> &, const std::unordered_map<std::string, std::string> &)> &handle) = 0;
        // when a message has been received
        virtual std::shared_ptr<IWSListener_Configuration>
        onMessage(const std::function<void(const std::shared_ptr<IWSocket> &, const WSMessage &)> &handle) = 0;
        // when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
        virtual std::shared_ptr<IWSListener_Configuration>
        onDisconnection(const std::function<void(const std::shared_ptr<IWSocket> &, unsigned short, const std::string &)> &handle) = 0;
        // when a ping is received from a client
        virtual std::shared_ptr<IWSListener_Configuration>
        onPing(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle) = 0;
        // when a pong is received from a client
        virtual std::shared_ptr<IWSListener_Configuration>
        onPong(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle) = 0;
        // start the process to listen for clients. This is non-blocking and will return immediatly
        virtual std::shared_ptr<IWSHub> listen(bool no_delay = true, bool reuse_address = true) = 0;
    };

    class WS_LITE_EXTERN IWSClient_Configuration {
      public:
        virtual ~IWSClient_Configuration() {}
        // when a connection is fully established.  If onconnect is called, then a matching onDisconnection is guaranteed
        virtual std::shared_ptr<IWSClient_Configuration>
        onConnection(const std::function<void(const std::shared_ptr<IWSocket> &, const std::unordered_map<std::string, std::string> &)> &handle) = 0;
        // when a message has been received
        virtual std::shared_ptr<IWSClient_Configuration>
        onMessage(const std::function<void(const std::shared_ptr<IWSocket> &, const WSMessage &)> &handle) = 0;
        // when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
        virtual std::shared_ptr<IWSClient_Configuration>
        onDisconnection(const std::function<void(const std::shared_ptr<IWSocket> &, unsigned short, const std::string &)> &handle) = 0;
        // when a ping is received from a client
        virtual std::shared_ptr<IWSClient_Configuration>
        onPing(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle) = 0;
        // when a pong is received from a client
        virtual std::shared_ptr<IWSClient_Configuration>
        onPong(const std::function<void(const std::shared_ptr<IWSocket> &, const unsigned char *, size_t)> &handle) = 0;
        // connect to an endpoint. This is non-blocking and will return immediatly. If the library is unable to establish a connection,
        // ondisconnection will be called.
        virtual std::shared_ptr<IWSHub> connect(const std::string &host, PortNumber port, bool no_delay = true, const std::string &endpoint = "/",
                                                const std::unordered_map<std::string, std::string> &extraheaders = {}) = 0;
    };

    class WS_LITE_EXTERN IWSContext_Configuration {
      public:
        virtual ~IWSContext_Configuration() {}

        virtual std::shared_ptr<IWSListener_Configuration> CreateListener(PortNumber port,
                                                                          ExtensionOptions options = ExtensionOptions::NO_OPTIONS) = 0;
        virtual std::shared_ptr<IWSClient_Configuration> CreateClient(ExtensionOptions options = ExtensionOptions::NO_OPTIONS) = 0;
    };
    class WS_LITE_EXTERN ITLS_Configuration {
      public:
        virtual ~ITLS_Configuration() {}
        virtual std::shared_ptr<IWSContext_Configuration> UseTLS(const std::function<void(TLSContext &context)> &callback, method m) = 0;
        virtual std::shared_ptr<IWSContext_Configuration> NoTLS() = 0;
    };

    std::shared_ptr<ITLS_Configuration> WS_LITE_EXTERN CreateContext(ThreadCount threadcount);
} // namespace WS_LITE
} // namespace SL
