#pragma once
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

typedef struct x509_store_ctx_st X509_STORE_CTX;

#if defined(WINDOWS) || defined(WIN32)
#if defined(WS_LITE_DLL)
#define WS_LITE_EXTERN __declspec(dllexport)
#else
#define WS_LITE_EXTERN
#endif
#else
#define WS_LITE_EXTERN
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
    // VDELETE is needed because some libraries like to defeine DELETE in the global namespace which causes errors
    enum class HttpVerbs { UNDEFINED, POST, GET, PUT, PATCH, VDELETE };
    enum class HttpVersions { UNDEFINED, HTTP1_0, HTTP1_1, HTTP2_0 };

    struct HeaderKeyValue {
        std::string_view Key;
        std::string_view Value;
    };

    struct HttpHeader {
        HttpVerbs Verb = HttpVerbs::UNDEFINED;
        HttpVersions HttpVersion = HttpVersions::UNDEFINED;
        int Code = 0;
        std::string_view UrlPart;
        std::vector<HeaderKeyValue> Values;
    };

    typedef Explicit<unsigned short, INTERNAL::PorNumbertTag> PortNumber;
    typedef Explicit<unsigned short, INTERNAL::ThreadCountTag> ThreadCount;

    enum options : unsigned long {
        default_workarounds = 0x80000BFFL,
        single_dh_use = 0x00100000L,
        no_sslv2 = 0x01000000L,
        no_sslv3 = 0x02000000L,
        no_tlsv1 = 0x04000000L,
        no_tlsv1_1 = 0x10000000L,
        no_tlsv1_2 = 0x08000000L,
        no_compression = 0x00020000L

    };
    enum password_purpose {
        /// The password is needed for reading/decryption.
        for_reading,

        /// The password is needed for writing/encryption.
        for_writing
    };
    enum file_format {
        /// ASN.1 file.
        asn1,

        /// PEM file.
        pem
    };
    enum method {
        /// Generic SSL version 2.
        sslv2,

        /// SSL version 2 client.
        sslv2_client,

        /// SSL version 2 server.
        sslv2_server,

        /// Generic SSL version 3.
        sslv3,

        /// SSL version 3 client.
        sslv3_client,

        /// SSL version 3 server.
        sslv3_server,

        /// Generic TLS version 1.
        tlsv1,

        /// TLS version 1 client.
        tlsv1_client,

        /// TLS version 1 server.
        tlsv1_server,

        /// Generic SSL/TLS.
        sslv23,

        /// SSL/TLS client.
        sslv23_client,

        /// SSL/TLS server.
        sslv23_server,

        /// Generic TLS version 1.1.
        tlsv11,

        /// TLS version 1.1 client.
        tlsv11_client,

        /// TLS version 1.1 server.
        tlsv11_server,

        /// Generic TLS version 1.2.
        tlsv12,

        /// TLS version 1.2 client.
        tlsv12_client,

        /// TLS version 1.2 server.
        tlsv12_server,

        /// Generic TLS.
        tls,

        /// TLS client.
        tls_client,

        /// TLS server.
        tls_server
    };
    enum verify_mode : int { verify_none = 0x00, verify_peer = 0x01, verify_fail_if_no_peer_cert = 0x02, verify_client_once = 0x04 };
    enum OpCode : unsigned char { CONTINUATION = 0, TEXT = 1, BINARY = 2, CLOSE = 8, PING = 9, PONG = 10, INVALID = 255 };
    enum SocketStatus : unsigned char { CONNECTING, CONNECTED, CLOSING, CLOSED };
    enum ExtensionOptions : unsigned char { NO_OPTIONS = 0, DEFLATE = 1 };
    enum class CompressionOptions { COMPRESS, NO_COMPRESSION };
    enum class NetworkProtocol { IPV4, IPV6 };

    struct WSMessage {
        unsigned char *data;
        size_t len;
        OpCode code;
        // buffer is here to ensure the lifetime of the unsigned char *data in this structure
        // users should set the *data variable to be the beginning of the data to send. Then, set the Buffer shared ptr as well to make sure the
        // lifetime of the data
        std::shared_ptr<unsigned char> Buffer;
    };

    class IWebSocket : public std::enable_shared_from_this<IWebSocket> {
      public:
        virtual ~IWebSocket() {}
        virtual SocketStatus is_open() const = 0;
        virtual std::string get_address() const = 0;
        virtual unsigned short get_port() const = 0;
        virtual bool is_v4() const = 0;
        virtual bool is_v6() const = 0;
        virtual bool is_loopback() const = 0;
        virtual size_t BufferedBytes() const = 0;
        virtual void send(const WSMessage &msg, CompressionOptions compressmessage) = 0;
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
        onConnection(const std::function<void(const std::shared_ptr<IWebSocket> &, const HttpHeader &)> &handle) = 0;
        // when a message has been received
        virtual std::shared_ptr<IWSListener_Configuration>
        onMessage(const std::function<void(const std::shared_ptr<IWebSocket> &, const WSMessage &)> &handle) = 0;
        // when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
        virtual std::shared_ptr<IWSListener_Configuration>
        onDisconnection(const std::function<void(const std::shared_ptr<IWebSocket> &, unsigned short, const std::string &)> &handle) = 0;
        // when a ping is received from a client
        virtual std::shared_ptr<IWSListener_Configuration>
        onPing(const std::function<void(const std::shared_ptr<IWebSocket> &, const unsigned char *, size_t)> &handle) = 0;
        // when a pong is received from a client
        virtual std::shared_ptr<IWSListener_Configuration>
        onPong(const std::function<void(const std::shared_ptr<IWebSocket> &, const unsigned char *, size_t)> &handle) = 0;
        // start the process to listen for clients. This is non-blocking and will return immediatly
        virtual std::shared_ptr<IWSHub> listen(bool no_delay = true, bool reuse_address = true) = 0;
    };

    class WS_LITE_EXTERN IWSClient_Configuration {
      public:
        virtual ~IWSClient_Configuration() {}
        // when a connection is fully established.  If onconnect is called, then a matching onDisconnection is guaranteed
        virtual std::shared_ptr<IWSClient_Configuration>
        onConnection(const std::function<void(const std::shared_ptr<IWebSocket> &, const HttpHeader &)> &handle) = 0;
        // when a message has been received
        virtual std::shared_ptr<IWSClient_Configuration>
        onMessage(const std::function<void(const std::shared_ptr<IWebSocket> &, const WSMessage &)> &handle) = 0;
        // when a socket is closed down for ANY reason. If onconnect is called, then a matching onDisconnection is guaranteed
        virtual std::shared_ptr<IWSClient_Configuration>
        onDisconnection(const std::function<void(const std::shared_ptr<IWebSocket> &, unsigned short, const std::string &)> &handle) = 0;
        // when a ping is received from a client
        virtual std::shared_ptr<IWSClient_Configuration>
        onPing(const std::function<void(const std::shared_ptr<IWebSocket> &, const unsigned char *, size_t)> &handle) = 0;
        // when a pong is received from a client
        virtual std::shared_ptr<IWSClient_Configuration>
        onPong(const std::function<void(const std::shared_ptr<IWebSocket> &, const unsigned char *, size_t)> &handle) = 0;
        // connect to an endpoint. This is non-blocking and will return immediatly. If the library is unable to establish a connection,
        // ondisconnection will be called.
        virtual std::shared_ptr<IWSHub> connect(const std::string &host, PortNumber port, bool no_delay = true, const std::string &endpoint = "/",
                                                const std::unordered_map<std::string, std::string> &extraheaders = {}) = 0;
    };

    class WS_LITE_EXTERN IWSContext_Configuration {
      public:
        virtual ~IWSContext_Configuration() {}

        virtual std::shared_ptr<IWSListener_Configuration> CreateListener(PortNumber port, NetworkProtocol protocol = NetworkProtocol::IPV4,
                                                                          ExtensionOptions options = ExtensionOptions::NO_OPTIONS) = 0;
        virtual std::shared_ptr<IWSClient_Configuration> CreateClient(ExtensionOptions options = ExtensionOptions::NO_OPTIONS) = 0;
    };
    class ITLSContext;
    class WS_LITE_EXTERN ITLS_Configuration {
      public:
        virtual ~ITLS_Configuration() {}
        virtual std::shared_ptr<IWSContext_Configuration> UseTLS(const std::function<void(ITLSContext *context)> &callback, method m) = 0;
        virtual std::shared_ptr<IWSContext_Configuration> NoTLS() = 0;
    };

    std::shared_ptr<ITLS_Configuration> WS_LITE_EXTERN CreateContext(ThreadCount threadcount);

    /*
    THE FOLLOWING IS JUST A THIN WRAPPER AROUND ASIO context.hpp
    THE PURPOSE IS SO USERS OF THIS LIBRARY DO NOT NEED TO INCLUDE ASIO IN THEIR PROJECT
    */

    class WS_LITE_EXTERN ITLSContext {
      public:
        virtual ~ITLSContext() {}

        /// Clear options on the context.
        /**
         * This function may be used to configure the SSL options used by the context.
         *
         * @param o A bitmask of options. The available option values are defined in
         * the context_base class. The specified options, if currently enabled on the
         * context, are cleared.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_clear_options.
         */
        virtual void clear_options(options o) = 0;

        /// Clear options on the context.
        /**
         * This function may be used to configure the SSL options used by the context.
         *
         * @param o A bitmask of options. The available option values are defined in
         * the context_base class. The specified options, if currently enabled on the
         * context, are cleared.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_clear_options.
         */
        virtual std::error_code clear_options(options o, std::error_code &ec) = 0;

        /// Set options on the context.
        /**
         * This function may be used to configure the SSL options used by the context.
         *
         * @param o A bitmask of options. The available option values are defined in
         * the context_base class. The options are bitwise-ored with any existing
         * value for the options.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_options.
         */
        virtual void set_options(unsigned long o) = 0;

        /// Set options on the context.
        /**
         * This function may be used to configure the SSL options used by the context.
         *
         * @param o A bitmask of options. The available option values are defined in
         * the context_base class. The options are bitwise-ored with any existing
         * value for the options.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_options.
         */
        virtual std::error_code set_options(options o, std::error_code &ec) = 0;

        /// Set the peer verification mode.
        /**
         * This function may be used to configure the peer verification mode used by
         * the context.
         *
         * @param v A bitmask of peer verification modes. See @ref verify_mode for
         * available values.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_verify.
         */
        virtual void set_verify_mode(verify_mode v) = 0;

        /// Set the peer verification mode.
        /**
         * This function may be used to configure the peer verification mode used by
         * the context.
         *
         * @param v A bitmask of peer verification modes. See @ref verify_mode for
         * available values.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_verify.
         */
        virtual std::error_code set_verify_mode(verify_mode v, std::error_code &ec) = 0;

        /// Set the peer verification depth.
        /**
         * This function may be used to configure the maximum verification depth
         * allowed by the context.
         *
         * @param depth Maximum depth for the certificate chain verification that
         * shall be allowed.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_verify_depth.
         */
        virtual void set_verify_depth(int depth) = 0;

        /// Set the peer verification depth.
        /**
         * This function may be used to configure the maximum verification depth
         * allowed by the context.
         *
         * @param depth Maximum depth for the certificate chain verification that
         * shall be allowed.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_verify_depth.
         */
        virtual std::error_code set_verify_depth(int depth, std::error_code &ec) = 0;

        /// Set the callback used to verify peer certificates.
        /**
         * This function is used to specify a callback function that will be called
         * by the implementation when it needs to verify a peer certificate.
         *
         * @param callback The function object to be used for verifying a certificate.
         * The function signature of the handler must be:
         * @code bool verify_callback(
         *   bool preverified, // True if the certificate passed pre-verification.
         *   X509_STORE_CTX* ctx // The peer certificate and other context.
         * )=0; @endcode
         * The return value of the callback is true if the certificate has passed
         * verification, false otherwise.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_verify.
         */
        virtual void set_verify_callback(const std::function<bool(bool, X509_STORE_CTX *)> &callback) = 0;

        /// Set the callback used to verify peer certificates.
        /**
         * This function is used to specify a callback function that will be called
         * by the implementation when it needs to verify a peer certificate.
         *
         * @param callback The function object to be used for verifying a certificate.
         * The function signature of the handler must be:
         * @code bool verify_callback(
         *   bool preverified, // True if the certificate passed pre-verification.
         *   verify_context& ctx // The peer certificate and other context.
         * )=0; @endcode
         * The return value of the callback is true if the certificate has passed
         * verification, false otherwise.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_verify.
         */
        virtual std::error_code set_verify_callback(const std::function<bool(bool, X509_STORE_CTX *)> &callback, std::error_code &ec) = 0;

        /// Load a certification authority file for performing verification.
        /**
         * This function is used to load one or more trusted certification authorities
         * from a file.
         *
         * @param filename The name of a file containing certification authority
         * certificates in PEM format.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_load_verify_locations.
         */
        virtual void load_verify_file(const std::string &filename) = 0;

        /// Load a certification authority file for performing verification.
        /**
         * This function is used to load the certificates for one or more trusted
         * certification authorities from a file.
         *
         * @param filename The name of a file containing certification authority
         * certificates in PEM format.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_load_verify_locations.
         */
        virtual std::error_code load_verify_file(const std::string &filename, std::error_code &ec) = 0;

        /// Add certification authority for performing verification.
        /**
         * This function is used to add one trusted certification authority
         * from a memory buffer.
         *
         * @param ca The buffer containing the certification authority certificate.
         * The certificate must use the PEM format.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_get_cert_store and @c X509_STORE_add_cert.
         */
        virtual void add_certificate_authority(const unsigned char *buffer, size_t buffer_size) = 0;

        /// Add certification authority for performing verification.
        /**
         * This function is used to add one trusted certification authority
         * from a memory buffer.
         *
         * @param ca The buffer containing the certification authority certificate.
         * The certificate must use the PEM format.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_get_cert_store and @c X509_STORE_add_cert.
         */
        virtual std::error_code add_certificate_authority(const unsigned char *buffer, size_t buffer_size, std::error_code &ec) = 0;

        /// Configures the context to use the default directories for finding
        /// certification authority certificates.
        /**
         * This function specifies that the context should use the default,
         * system-dependent directories for locating certification authority
         * certificates.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_default_verify_paths.
         */
        virtual void set_default_verify_paths() = 0;

        /// Configures the context to use the default directories for finding
        /// certification authority certificates.
        /**
         * This function specifies that the context should use the default,
         * system-dependent directories for locating certification authority
         * certificates.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_default_verify_paths.
         */
        virtual std::error_code set_default_verify_paths(std::error_code &ec) = 0;

        /// Add a directory containing certificate authority files to be used for
        /// performing verification.
        /**
         * This function is used to specify the name of a directory containing
         * certification authority certificates. Each file in the directory must
         * contain a single certificate. The files must be named using the subject
         * name's hash and an extension of ".0".
         *
         * @param path The name of a directory containing the certificates.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_load_verify_locations.
         */
        virtual void add_verify_path(const std::string &path) = 0;

        /// Add a directory containing certificate authority files to be used for
        /// performing verification.
        /**
         * This function is used to specify the name of a directory containing
         * certification authority certificates. Each file in the directory must
         * contain a single certificate. The files must be named using the subject
         * name's hash and an extension of ".0".
         *
         * @param path The name of a directory containing the certificates.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_load_verify_locations.
         */
        virtual std::error_code add_verify_path(const std::string &path, std::error_code &ec) = 0;

        /// Use a certificate from a memory buffer.
        /**
         * This function is used to load a certificate into the context from a buffer.
         *
         * @param certificate The buffer containing the certificate.
         *
         * @param format The certificate format (ASN.1 or PEM).
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_use_certificate or SSL_CTX_use_certificate_ASN1.
         */
        virtual void use_certificate(const unsigned char *buffer, size_t buffer_size, file_format format) = 0;

        /// Use a certificate from a memory buffer.
        /**
         * This function is used to load a certificate into the context from a buffer.
         *
         * @param certificate The buffer containing the certificate.
         *
         * @param format The certificate format (ASN.1 or PEM).
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_use_certificate or SSL_CTX_use_certificate_ASN1.
         */
        virtual std::error_code use_certificate(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec) = 0;

        /// Use a certificate from a file.
        /**
         * This function is used to load a certificate into the context from a file.
         *
         * @param filename The name of the file containing the certificate.
         *
         * @param format The file format (ASN.1 or PEM).
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_use_certificate_file.
         */
        virtual void use_certificate_file(const std::string &filename, file_format format) = 0;

        /// Use a certificate from a file.
        /**
         * This function is used to load a certificate into the context from a file.
         *
         * @param filename The name of the file containing the certificate.
         *
         * @param format The file format (ASN.1 or PEM).
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_use_certificate_file.
         */
        virtual std::error_code use_certificate_file(const std::string &filename, file_format format, std::error_code &ec) = 0;

        /// Use a certificate chain from a memory buffer.
        /**
         * This function is used to load a certificate chain into the context from a
         * buffer.
         *
         * @param chain The buffer containing the certificate chain. The certificate
         * chain must use the PEM format.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_use_certificate and SSL_CTX_add_extra_chain_cert.
         */
        virtual void use_certificate_chain(const unsigned char *buffer, size_t buffer_size) = 0;

        /// Use a certificate chain from a memory buffer.
        /**
         * This function is used to load a certificate chain into the context from a
         * buffer.
         *
         * @param chain The buffer containing the certificate chain. The certificate
         * chain must use the PEM format.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_use_certificate and SSL_CTX_add_extra_chain_cert.
         */
        virtual std::error_code use_certificate_chain(const unsigned char *buffer, size_t buffer_size, std::error_code &ec) = 0;

        /// Use a certificate chain from a file.
        /**
         * This function is used to load a certificate chain into the context from a
         * file.
         *
         * @param filename The name of the file containing the certificate. The file
         * must use the PEM format.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_use_certificate_chain_file.
         */
        virtual void use_certificate_chain_file(const std::string &filename) = 0;

        /// Use a certificate chain from a file.
        /**
         * This function is used to load a certificate chain into the context from a
         * file.
         *
         * @param filename The name of the file containing the certificate. The file
         * must use the PEM format.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_use_certificate_chain_file.
         */
        virtual std::error_code use_certificate_chain_file(const std::string &filename, std::error_code &ec) = 0;

        /// Use a private key from a memory buffer.
        /**
         * This function is used to load a private key into the context from a buffer.
         *
         * @param private_key The buffer containing the private key.
         *
         * @param format The private key format (ASN.1 or PEM).
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_use_PrivateKey or SSL_CTX_use_PrivateKey_ASN1.
         */
        virtual void use_private_key(const unsigned char *buffer, size_t buffer_size, file_format format) = 0;

        /// Use a private key from a memory buffer.
        /**
         * This function is used to load a private key into the context from a buffer.
         *
         * @param private_key The buffer containing the private key.
         *
         * @param format The private key format (ASN.1 or PEM).
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_use_PrivateKey or SSL_CTX_use_PrivateKey_ASN1.
         */
        virtual std::error_code use_private_key(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec) = 0;

        /// Use a private key from a file.
        /**
         * This function is used to load a private key into the context from a file.
         *
         * @param filename The name of the file containing the private key.
         *
         * @param format The file format (ASN.1 or PEM).
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_use_PrivateKey_file.
         */
        virtual void use_private_key_file(const std::string &filename, file_format format) = 0;

        /// Use a private key from a file.
        /**
         * This function is used to load a private key into the context from a file.
         *
         * @param filename The name of the file containing the private key.
         *
         * @param format The file format (ASN.1 or PEM).
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_use_PrivateKey_file.
         */
        virtual std::error_code use_private_key_file(const std::string &filename, file_format format, std::error_code &ec) = 0;

        /// Use an RSA private key from a memory buffer.
        /**
         * This function is used to load an RSA private key into the context from a
         * buffer.
         *
         * @param private_key The buffer containing the RSA private key.
         *
         * @param format The private key format (ASN.1 or PEM).
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_use_RSAPrivateKey or SSL_CTX_use_RSAPrivateKey_ASN1.
         */
        virtual void use_rsa_private_key(const unsigned char *buffer, size_t buffer_size, file_format format) = 0;

        /// Use an RSA private key from a memory buffer.
        /**
         * This function is used to load an RSA private key into the context from a
         * buffer.
         *
         * @param private_key The buffer containing the RSA private key.
         *
         * @param format The private key format (ASN.1 or PEM).
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_use_RSAPrivateKey or SSL_CTX_use_RSAPrivateKey_ASN1.
         */
        virtual std::error_code use_rsa_private_key(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec) = 0;

        /// Use an RSA private key from a file.
        /**
         * This function is used to load an RSA private key into the context from a
         * file.
         *
         * @param filename The name of the file containing the RSA private key.
         *
         * @param format The file format (ASN.1 or PEM).
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_use_RSAPrivateKey_file.
         */
        virtual void use_rsa_private_key_file(const std::string &filename, file_format format) = 0;

        /// Use an RSA private key from a file.
        /**
         * This function is used to load an RSA private key into the context from a
         * file.
         *
         * @param filename The name of the file containing the RSA private key.
         *
         * @param format The file format (ASN.1 or PEM).
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_use_RSAPrivateKey_file.
         */
        virtual std::error_code use_rsa_private_key_file(const std::string &filename, file_format format, std::error_code &ec) = 0;

        /// Use the specified memory buffer to obtain the temporary Diffie-Hellman
        /// parameters.
        /**
         * This function is used to load Diffie-Hellman parameters into the context
         * from a buffer.
         *
         * @param dh The memory buffer containing the Diffie-Hellman parameters. The
         * buffer must use the PEM format.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_tmp_dh.
         */
        virtual void use_tmp_dh(const unsigned char *buffer, size_t buffer_size) = 0;

        /// Use the specified memory buffer to obtain the temporary Diffie-Hellman
        /// parameters.
        /**
         * This function is used to load Diffie-Hellman parameters into the context
         * from a buffer.
         *
         * @param dh The memory buffer containing the Diffie-Hellman parameters. The
         * buffer must use the PEM format.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_tmp_dh.
         */
        virtual std::error_code use_tmp_dh(const unsigned char *buffer, size_t buffer_size, std::error_code &ec) = 0;

        /// Use the specified file to obtain the temporary Diffie-Hellman parameters.
        /**
         * This function is used to load Diffie-Hellman parameters into the context
         * from a file.
         *
         * @param filename The name of the file containing the Diffie-Hellman
         * parameters. The file must use the PEM format.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_tmp_dh.
         */
        virtual void use_tmp_dh_file(const std::string &filename) = 0;

        /// Use the specified file to obtain the temporary Diffie-Hellman parameters.
        /**
         * This function is used to load Diffie-Hellman parameters into the context
         * from a file.
         *
         * @param filename The name of the file containing the Diffie-Hellman
         * parameters. The file must use the PEM format.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_tmp_dh.
         */
        virtual std::error_code use_tmp_dh_file(const std::string &filename, std::error_code &ec) = 0;

        /// Set the password callback.
        /**
         * This function is used to specify a callback function to obtain password
         * information about an encrypted key in PEM format.
         *
         * @param callback The function object to be used for obtaining the password.
         * The function signature of the handler must be:
         * @code std::string password_callback(
         *   std::size_t max_length,  // The maximum size for a password.
         *   password_purpose purpose // Whether password is for reading or writing.
         * )=0; @endcode
         * The return value of the callback is a string containing the password.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_default_passwd_cb.
         */
        virtual void set_password_callback(const std::function<std::string(std::size_t, password_purpose)> &callback) = 0;

        /// Set the password callback.
        /**
         * This function is used to specify a callback function to obtain password
         * information about an encrypted key in PEM format.
         *
         * @param callback The function object to be used for obtaining the password.
         * The function signature of the handler must be:
         * @code std::string password_callback(
         *   std::size_t max_length,  // The maximum size for a password.
         *   password_purpose purpose // Whether password is for reading or writing.
         * ); @endcode
         * The return value of the callback is a string containing the password.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_default_passwd_cb.
         */
        virtual std::error_code set_password_callback(const std::function<std::string(std::size_t, password_purpose)> &callback,
                                                      std::error_code &ec) = 0;
    };
} // namespace WS_LITE
} // namespace SL
