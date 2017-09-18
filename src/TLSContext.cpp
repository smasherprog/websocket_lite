#include "TLSContext.h"
#include "internal/DataStructures.h"
#if WIN32
#include <SDKDDKVer.h>
#endif

#include "asio.hpp"
#include "asio/deadline_timer.hpp"
#include "asio/ssl.hpp"

namespace SL {
namespace WS_LITE {

    void TLSContext::clear_options(options o) { impl->sslcontext.clear_options(o); }
    std::error_code TLSContext::clear_options(options o, std::error_code &ec) { impl->sslcontext.clear_options(o, ec); }
    void TLSContext::set_options(options o) { impl->sslcontext.set_options(o); }
    std::error_code TLSContext::set_options(options o, std::error_code &ec) { impl->sslcontext.set_options(o, ec); }
    void TLSContext::set_verify_mode(verify_mode v) { impl->sslcontext.set_verify_mode(v); }
    std::error_code TLSContext::set_verify_mode(verify_mode v, std::error_code &ec) { impl->sslcontext.set_verify_mode(v, ec); }
    void TLSContext::set_verify_depth(int depth) { impl->sslcontext.set_verify_depth(depth); }
    std::error_code TLSContext::set_verify_depth(int depth, std::error_code &ec) { impl->sslcontext.set_verify_depth(depth, ec); }
    void TLSContext::set_verify_callback(const std::function<bool(bool preverified, X509_STORE_CTX *)> &callback)
    {
        impl->sslcontext.set_verify_callback([callback](bool p, asio::ssl::verify_context &ctx) { return callback(p, ctx.native_handle()); });
    }

    std::error_code TLSContext::set_verify_callback(const std::function<bool(bool preverified, X509_STORE_CTX *)> &callback, std::error_code &ec)
    {
        impl->sslcontext.set_verify_callback([callback](bool p, asio::ssl::verify_context &ctx) { return callback(p, ctx.native_handle()); }, ec);
    }

    void TLSContext::load_verify_file(const std::string &filename) { impl->sslcontext.load_verify_file(filename); }

    std::error_code TLSContext::load_verify_file(const std::string &filename, std::error_code &ec)
    {
        impl->sslcontext.load_verify_file(filename, ec);
    }

    void TLSContext::add_certificate_authority(const unsigned char *buffer, size_t buffer_size)
    {
        impl->sslcontext.add_certificate_authority(asio::const_buffer(buffer, buffer_size));
    }

    std::error_code TLSContext::add_certificate_authority(const unsigned char *buffer, size_t buffer_size, std::error_code &ec)
    {
        impl->sslcontext.add_certificate_authority(asio::const_buffer(buffer, buffer_size), ec);
    }

    void TLSContext::set_default_verify_paths()
    {
        std::error_code ec;
        impl->sslcontext.set_default_verify_paths(ec);
    }

    std::error_code TLSContext::set_default_verify_paths(std::error_code &ec)
    {
        impl->sslcontext.set_default_verify_paths(ec);

#if WIN32
        HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
        if (hStore == NULL) {
            return;
        }

        X509_STORE *store = X509_STORE_new();
        PCCERT_CONTEXT pContext = NULL;
        while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
            // convert from DER to internal format
            X509 *x509 = d2i_X509(NULL, (const unsigned char **)&pContext->pbCertEncoded, pContext->cbCertEncoded);
            if (x509 != NULL) {
                X509_STORE_add_cert(store, x509);
                X509_free(x509);
            }
        }

        CertFreeCertificateContext(pContext);
        CertCloseStore(hStore, 0);

        // attach X509_STORE to boost ssl context
        SSL_CTX_set_cert_store(impl->sslcontext.native_handle(), store);

#endif
    }

    void TLSContext::add_verify_path(const std::string &path) { impl->sslcontext.add_verify_path(path); }

    std::error_code TLSContext::add_verify_path(const std::string &path, std::error_code &ec) { impl->sslcontext.add_verify_path(path, ec); }

    void TLSContext::use_certificate(const unsigned char *buffer, size_t buffer_size, file_format format)
    {
        impl->sslcontext.use_certificate(asio::const_buffer(buffer, buffer_size), static_cast<asio::ssl::context_base::file_format>(format));
    }

    std::error_code TLSContext::use_certificate(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec)
    {
        impl->sslcontext.use_certificate(asio::const_buffer(buffer, buffer_size), static_cast<asio::ssl::context_base::file_format>(format), ec);
    }

    void TLSContext::use_certificate_file(const std::string &filename, file_format format)
    {
        impl->sslcontext.use_certificate_file(filename, static_cast<asio::ssl::context_base::file_format>(format));
    }
    std::error_code TLSContext::use_certificate_file(const std::string &filename, file_format format, std::error_code &ec)
    {
        impl->sslcontext.use_certificate_file(filename, static_cast<asio::ssl::context_base::file_format>(format), ec);
    }

    void TLSContext::use_certificate_chain(const unsigned char *buffer, size_t buffer_size)
    {
        impl->sslcontext.use_certificate_chain(asio::const_buffer(buffer, buffer_size));
    }

    std::error_code TLSContext::use_certificate_chain(const unsigned char *buffer, size_t buffer_size, std::error_code &ec)
    {
        impl->sslcontext.use_certificate_chain(asio::const_buffer(buffer, buffer_size), ec);
    }

    void TLSContext::use_certificate_chain_file(const std::string &filename) { impl->sslcontext.use_certificate_chain_file(filename); }

    std::error_code TLSContext::use_certificate_chain_file(const std::string &filename, std::error_code &ec)
    {
        impl->sslcontext.use_certificate_chain_file(filename, ec);
    }

    void TLSContext::use_private_key(const unsigned char *buffer, size_t buffer_size, file_format format)
    {
        impl->sslcontext.use_private_key(asio::const_buffer(buffer, buffer_size), static_cast<asio::ssl::context_base::file_format>(format));
    }

    std::error_code TLSContext::use_private_key(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec)
    {
        impl->sslcontext.use_private_key(asio::const_buffer(buffer, buffer_size), static_cast<asio::ssl::context_base::file_format>(format), ec);
    }

    void TLSContext::use_private_key_file(const std::string &filename, file_format format)
    {
        impl->sslcontext.use_private_key_file(filename, static_cast<asio::ssl::context_base::file_format>(format));
    }

    std::error_code TLSContext::use_private_key_file(const std::string &filename, file_format format, std::error_code &ec)
    {
        impl->sslcontext.use_private_key_file(filename, static_cast<asio::ssl::context_base::file_format>(format), ec);
    }

    void TLSContext::use_rsa_private_key(const unsigned char *buffer, size_t buffer_size, file_format format)
    {
        impl->sslcontext.use_rsa_private_key(asio::const_buffer(buffer, buffer_size), static_cast<asio::ssl::context_base::file_format>(format));
    }

    std::error_code TLSContext::use_rsa_private_key(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec)
    {
        impl->sslcontext.use_rsa_private_key(asio::const_buffer(buffer, buffer_size), static_cast<asio::ssl::context_base::file_format>(format), ec);
    }

    void TLSContext::use_rsa_private_key_file(const std::string &filename, file_format format)
    {
        impl->sslcontext.use_rsa_private_key_file(filename, static_cast<asio::ssl::context_base::file_format>(format));
    }

    std::error_code TLSContext::use_rsa_private_key_file(const std::string &filename, file_format format, std::error_code &ec)
    {
        impl->sslcontext.use_rsa_private_key_file(filename, static_cast<asio::ssl::context_base::file_format>(format), ec);
    }

    void TLSContext::use_tmp_dh(const unsigned char *buffer, size_t buffer_size)
    {
        impl->sslcontext.use_tmp_dh(asio::const_buffer(buffer, buffer_size));
    }

    std::error_code TLSContext::use_tmp_dh(const unsigned char *buffer, size_t buffer_size, std::error_code &ec)
    {
        impl->sslcontext.use_tmp_dh(asio::const_buffer(buffer, buffer_size), ec);
    }

    void TLSContext::use_tmp_dh_file(const std::string &filename) { impl->sslcontext.use_tmp_dh_file(filename); }

    std::error_code TLSContext::use_tmp_dh_file(const std::string &filename, std::error_code &ec) { impl->sslcontext.use_tmp_dh_file(filename, ec); }

    void TLSContext::set_password_callback(std::function<std::string(std::size_t, password_purpose)> &callback)
    {

        impl->sslcontext.set_password_callback(
            [callback](std::size_t s, asio::ssl::context_base::password_purpose p) { return callback(s, static_cast<password_purpose>(p)); });
    }

    std::error_code TLSContext::set_password_callback(std::function<std::string(std::size_t, password_purpose)> &callback, asio::error_code &ec)
    {

        impl->sslcontext.set_password_callback(
            [callback](std::size_t s, asio::ssl::context_base::password_purpose p) { return callback(s, static_cast<password_purpose>(p)); }, ec);
    }

} // namespace WS_LITE
} // namespace SL