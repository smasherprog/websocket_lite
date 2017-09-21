#include "WS_Lite.h"
#include "internal/WebSocketProtocol.h"
#include <memory>

namespace SL {
namespace WS_LITE {
    class TLSContext : public ITLSContext {
        std::shared_ptr<WSContextImpl> WSContextImpl_;

      public:
        TLSContext(const std::shared_ptr<WSContextImpl> &c) : WSContextImpl_(c) {}
        virtual ~TLSContext() {}

        virtual void clear_options(options o) override { WSContextImpl_->sslcontext.clear_options(o); }
        virtual std::error_code clear_options(options o, std::error_code &ec) override { return WSContextImpl_->sslcontext.clear_options(o, ec); }
        virtual void set_options(unsigned long o) override { WSContextImpl_->sslcontext.set_options(o); }
        virtual std::error_code set_options(options o, std::error_code &ec) override { return WSContextImpl_->sslcontext.set_options(o, ec); }
        virtual void set_verify_mode(verify_mode v) override { WSContextImpl_->sslcontext.set_verify_mode(v); }
        virtual std::error_code set_verify_mode(verify_mode v, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.set_verify_mode(v, ec);
        }
        virtual void set_verify_depth(int depth) override { WSContextImpl_->sslcontext.set_verify_depth(depth); }
        virtual std::error_code set_verify_depth(int depth, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.set_verify_depth(depth, ec);
        }
        virtual void set_verify_callback(const std::function<bool(bool preverified, X509_STORE_CTX *)> &callback) override
        {
            WSContextImpl_->sslcontext.set_verify_callback(
                [callback](bool p, asio::ssl::verify_context &ctx) { return callback(p, ctx.native_handle()); });
        }

        virtual std::error_code set_verify_callback(const std::function<bool(bool preverified, X509_STORE_CTX *)> &callback,
                                                    std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.set_verify_callback(
                [callback](bool p, asio::ssl::verify_context &ctx) { return callback(p, ctx.native_handle()); }, ec);
        }

        virtual void load_verify_file(const std::string &filename) override { WSContextImpl_->sslcontext.load_verify_file(filename); }

        virtual std::error_code load_verify_file(const std::string &filename, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.load_verify_file(filename, ec);
        }

        virtual void add_certificate_authority(const unsigned char *buffer, size_t buffer_size) override
        {
            WSContextImpl_->sslcontext.add_certificate_authority(asio::const_buffer(buffer, buffer_size));
        }

        virtual std::error_code add_certificate_authority(const unsigned char *buffer, size_t buffer_size, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.add_certificate_authority(asio::const_buffer(buffer, buffer_size), ec);
        }

        virtual void set_default_verify_paths() override
        {
            std::error_code ec;
            set_default_verify_paths(ec);
        }

        virtual std::error_code set_default_verify_paths(std::error_code &ec) override
        {
#if WIN32
            HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
            if (hStore != NULL) {

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
                SSL_CTX_set_cert_store(WSContextImpl_->sslcontext.native_handle(), store);
            }
#endif
            return WSContextImpl_->sslcontext.set_default_verify_paths(ec);
        }

        virtual void add_verify_path(const std::string &path) override { WSContextImpl_->sslcontext.add_verify_path(path); }

        virtual std::error_code add_verify_path(const std::string &path, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.add_verify_path(path, ec);
        }

        virtual void use_certificate(const unsigned char *buffer, size_t buffer_size, file_format format) override
        {
            WSContextImpl_->sslcontext.use_certificate(asio::const_buffer(buffer, buffer_size),
                                                       static_cast<asio::ssl::context_base::file_format>(format));
        }

        virtual std::error_code use_certificate(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_certificate(asio::const_buffer(buffer, buffer_size),
                                                              static_cast<asio::ssl::context_base::file_format>(format), ec);
        }

        virtual void use_certificate_file(const std::string &filename, file_format format) override
        {
            WSContextImpl_->sslcontext.use_certificate_file(filename, static_cast<asio::ssl::context_base::file_format>(format));
        }
        virtual std::error_code use_certificate_file(const std::string &filename, file_format format, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_certificate_file(filename, static_cast<asio::ssl::context_base::file_format>(format), ec);
        }

        virtual void use_certificate_chain(const unsigned char *buffer, size_t buffer_size) override
        {
            WSContextImpl_->sslcontext.use_certificate_chain(asio::const_buffer(buffer, buffer_size));
        }

        virtual std::error_code use_certificate_chain(const unsigned char *buffer, size_t buffer_size, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_certificate_chain(asio::const_buffer(buffer, buffer_size), ec);
        }

        virtual void use_certificate_chain_file(const std::string &filename) override
        {
            WSContextImpl_->sslcontext.use_certificate_chain_file(filename);
        }

        virtual std::error_code use_certificate_chain_file(const std::string &filename, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_certificate_chain_file(filename, ec);
        }

        virtual void use_private_key(const unsigned char *buffer, size_t buffer_size, file_format format) override
        {
            WSContextImpl_->sslcontext.use_private_key(asio::const_buffer(buffer, buffer_size),
                                                       static_cast<asio::ssl::context_base::file_format>(format));
        }

        virtual std::error_code use_private_key(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_private_key(asio::const_buffer(buffer, buffer_size),
                                                              static_cast<asio::ssl::context_base::file_format>(format), ec);
        }

        virtual void use_private_key_file(const std::string &filename, file_format format) override
        {
            WSContextImpl_->sslcontext.use_private_key_file(filename, static_cast<asio::ssl::context_base::file_format>(format));
        }

        virtual std::error_code use_private_key_file(const std::string &filename, file_format format, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_private_key_file(filename, static_cast<asio::ssl::context_base::file_format>(format), ec);
        }

        virtual void use_rsa_private_key(const unsigned char *buffer, size_t buffer_size, file_format format) override
        {
            WSContextImpl_->sslcontext.use_rsa_private_key(asio::const_buffer(buffer, buffer_size),
                                                           static_cast<asio::ssl::context_base::file_format>(format));
        }

        virtual std::error_code use_rsa_private_key(const unsigned char *buffer, size_t buffer_size, file_format format, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_rsa_private_key(asio::const_buffer(buffer, buffer_size),
                                                                  static_cast<asio::ssl::context_base::file_format>(format), ec);
        }

        virtual void use_rsa_private_key_file(const std::string &filename, file_format format) override
        {
            WSContextImpl_->sslcontext.use_rsa_private_key_file(filename, static_cast<asio::ssl::context_base::file_format>(format));
        }

        virtual std::error_code use_rsa_private_key_file(const std::string &filename, file_format format, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_rsa_private_key_file(filename, static_cast<asio::ssl::context_base::file_format>(format), ec);
        }

        virtual void use_tmp_dh(const unsigned char *buffer, size_t buffer_size) override
        {
            WSContextImpl_->sslcontext.use_tmp_dh(asio::const_buffer(buffer, buffer_size));
        }

        virtual std::error_code use_tmp_dh(const unsigned char *buffer, size_t buffer_size, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_tmp_dh(asio::const_buffer(buffer, buffer_size), ec);
        }

        virtual void use_tmp_dh_file(const std::string &filename) override { WSContextImpl_->sslcontext.use_tmp_dh_file(filename); }

        virtual std::error_code use_tmp_dh_file(const std::string &filename, std::error_code &ec) override
        {
            return WSContextImpl_->sslcontext.use_tmp_dh_file(filename, ec);
        }

        virtual void set_password_callback(const std::function<std::string(std::size_t, password_purpose)> &callback) override
        {

            WSContextImpl_->sslcontext.set_password_callback(
                [callback](std::size_t s, asio::ssl::context_base::password_purpose p) { return callback(s, static_cast<password_purpose>(p)); });
        }

        virtual std::error_code set_password_callback(const std::function<std::string(std::size_t, password_purpose)> &callback,
                                                      asio::error_code &ec) override
        {

            return WSContextImpl_->sslcontext.set_password_callback(
                [callback](std::size_t s, asio::ssl::context_base::password_purpose p) { return callback(s, static_cast<password_purpose>(p)); }, ec);
        }
    };

    class WSContext_Configuration : public IWSContext_Configuration {
        std::shared_ptr<WSContextImpl> WSContextImpl_;

      public:
        WSContext_Configuration(const std::shared_ptr<WSContextImpl> &c) : WSContextImpl_(c) {}
        virtual ~WSContext_Configuration() {}

        virtual std::shared_ptr<IWSListener_Configuration> CreateListener(PortNumber port, ExtensionOptions options) override
        {
            UNUSED(options);
            WSContextImpl_->acceptor =
                std::make_unique<asio::ip::tcp::acceptor>(WSContextImpl_->io_service, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port.value));
            return std::make_shared<WSListener_Configuration>(WSContextImpl_);
        }
        virtual std::shared_ptr<IWSClient_Configuration> CreateClient(ExtensionOptions options) override
        {
            UNUSED(options);
            return std::make_shared<WSClient_Configuration>(WSContextImpl_);
        }
    };
    class TLS_Configuration : public ITLS_Configuration {
        std::shared_ptr<DelayedInfo> WSContextImpl_;

      public:
        TLS_Configuration(const std::shared_ptr<DelayedInfo> &c) : WSContextImpl_(c) {}
        virtual ~TLS_Configuration() {}

        virtual std::shared_ptr<IWSContext_Configuration> UseTLS(const std::function<void(ITLSContext *context)> &callback, method m) override
        {
            auto ret = std::make_shared<WSContextImpl>(WSContextImpl_->threadcount, m);
            ret->TLSEnabled = true;
            TLSContext tlscontext(ret);
            callback(&tlscontext);
            return std::make_shared<WSContext_Configuration>(ret);
        }
        virtual std::shared_ptr<IWSContext_Configuration> NoTLS() override
        {
            auto ret = std::make_shared<WSContextImpl>(WSContextImpl_->threadcount);
            ret->TLSEnabled = false;
            return std::make_shared<WSContext_Configuration>(ret);
        }
    };
    std::shared_ptr<ITLS_Configuration> CreateContext(ThreadCount threadcount)
    {
        auto ret = std::make_shared<DelayedInfo>();
        ret->threadcount = threadcount;
        return std::make_shared<TLS_Configuration>(ret);
    }

} // namespace WS_LITE
} // namespace SL
