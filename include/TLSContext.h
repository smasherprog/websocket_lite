#pragma once

#include "openssl/ssl.h"
#include <functional>
#include <memory>
#include <string>
#if WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wincrypt.h>
#endif

namespace SL {
namespace WS_LITE {
    /*
    THE FOLLOWING IS JUST A THIN WRAPPER AROUND ASIO context.hpp
    THE PURPOSE IS SO USERS OF THIS LIBRARY DO NOT NEED TO INCLUDE ASIO IN THEIR PROJECT
    */

    enum options : unsigned long {
        default_workarounds = SSL_OP_ALL,
        single_dh_use = SSL_OP_SINGLE_DH_USE,
        no_sslv2 = SSL_OP_NO_SSLv2,
        no_sslv3 = SSL_OP_NO_SSLv3,
        no_tlsv1 = SSL_OP_NO_TLSv1,
#if defined(SSL_OP_NO_TLSv1_1)
        no_tlsv1_1 = SSL_OP_NO_TLSv1_1,
#else  // defined(SSL_OP_NO_TLSv1_1)
        no_tlsv1_1 = 0x10000000L,
#endif // defined(SSL_OP_NO_TLSv1_1)
#if defined(SSL_OP_NO_TLSv1_2)
        no_tlsv1_2 = SSL_OP_NO_TLSv1_2,
#else  // defined(SSL_OP_NO_TLSv1_2)
        no_tlsv1_2 = 0x08000000L,
#endif // defined(SSL_OP_NO_TLSv1_2)
#if defined(SSL_OP_NO_COMPRESSION)
        no_compression = SSL_OP_NO_COMPRESSION
#else  // defined(SSL_OP_NO_COMPRESSION)
        no_compression = 0x20000L
#endif // defined(SSL_OP_NO_COMPRESSION)
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
    enum verify_mode : int {
        verify_none = SSL_VERIFY_NONE,
        verify_peer = SSL_VERIFY_PEER,
        verify_fail_if_no_peer_cert = SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_client_once = SSL_VERIFY_CLIENT_ONCE
    };
    struct WSContextImpl;
    class TLSContext {
      public:
        std::shared_ptr<WSContextImpl> impl;
        TLSContext() {}
        ~TLSContext() {}

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
        void clear_options(options o);

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
        std::error_code clear_options(options o, std::error_code &ec);

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
        void set_options(options o);

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
        std::error_code set_options(options o, std::error_code &ec);

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
        void set_verify_mode(verify_mode v);

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
        std::error_code set_verify_mode(verify_mode v, std::error_code &ec);

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
        void set_verify_depth(int depth);

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
        std::error_code set_verify_depth(int depth, std::error_code &ec);

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
         * ); @endcode
         * The return value of the callback is true if the certificate has passed
         * verification, false otherwise.
         *
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_verify.
         */
        void set_verify_callback(const std::function<bool(bool preverified, X509_STORE_CTX *)> &callback);

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
         * ); @endcode
         * The return value of the callback is true if the certificate has passed
         * verification, false otherwise.
         *
         * @param ec Set to indicate what error occurred, if any.
         *
         * @note Calls @c SSL_CTX_set_verify.
         */
        std::error_code set_verify_callback(const std::function<bool(bool preverified, X509_STORE_CTX *)> &callback, std::error_code &ec);

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
        void load_verify_file(const std::string &filename);

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
        std::error_code load_verify_file(const std::string &filename, std::error_code &ec);

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
        void add_certificate_authority(const unsigned char *buffer, size_t buffer_size);

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
        std::error_code add_certificate_authority(const unsigned char *buffer, size_t buffer_size, std::error_code &ec);

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
        void set_default_verify_paths();

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
        std::error_code set_default_verify_paths(std::error_code &ec);

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
        void add_verify_path(const std::string &path);

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
        std::error_code add_verify_path(const std::string &path, std::error_code &ec);

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
        void use_certificate(const unsigned char *buffer, size_t buffer_size, file_format format);

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
        std::error_code use_certificate(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec);

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
        void use_certificate_file(const std::string &filename, file_format format);

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
        std::error_code use_certificate_file(const std::string &filename, file_format format, std::error_code &ec);

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
        void use_certificate_chain(const unsigned char *buffer, size_t buffer_size);

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
        std::error_code use_certificate_chain(const unsigned char *buffer, size_t buffer_size, std::error_code &ec);

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
        void use_certificate_chain_file(const std::string &filename);

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
        std::error_code use_certificate_chain_file(const std::string &filename, std::error_code &ec);

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
        void use_private_key(const unsigned char *buffer, size_t buffer_size, file_format format);

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
        std::error_code use_private_key(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec);

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
        void use_private_key_file(const std::string &filename, file_format format);

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
        std::error_code use_private_key_file(const std::string &filename, file_format format, std::error_code &ec);

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
        void use_rsa_private_key(const unsigned char *buffer, size_t buffer_size, file_format format);

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
        std::error_code use_rsa_private_key(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec);

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
        void use_rsa_private_key_file(const std::string &filename, file_format format);

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
        std::error_code use_rsa_private_key_file(const std::string &filename, file_format format, std::error_code &ec);

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
        void use_tmp_dh(const unsigned char *buffer, size_t buffer_size);

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
        std::error_code use_tmp_dh(const unsigned char *buffer, size_t buffer_size, std::error_code &ec);

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
        void use_tmp_dh_file(const std::string &filename);

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
        std::error_code use_tmp_dh_file(const std::string &filename, std::error_code &ec);

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
         * @throws asio::system_error Thrown on failure.
         *
         * @note Calls @c SSL_CTX_set_default_passwd_cb.
         */
        void set_password_callback(std::function<std::string(std::size_t, password_purpose)> &callback);

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
        std::error_code set_password_callback(std::function<std::string(std::size_t, password_purpose)> &callback, std::error_code &ec);

    }; // namespace WS_LITE

} // namespace WS_LITE
} // namespace SL