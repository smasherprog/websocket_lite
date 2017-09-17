#include "TLS.h"
#include "internal/DataStructures.h"
#if WIN32
#include <SDKDDKVer.h>
#endif

#include "asio.hpp"
#include "asio/deadline_timer.hpp"
#include "asio/ssl.hpp"

namespace SL {
namespace WS_LITE {

    context::context(method m) { impl = std::make_shared<TLSContext>(m); }
    context::~context() {}

    void context::clear_options(options o) { impl->sslcontext.clear_options(o); }
    std::error_code context::clear_options(options o, std::error_code &ec) { impl->sslcontext.clear_options(o, ec); }
    void context::set_options(options o) { impl->sslcontext.set_options(o); }
    std::error_code context::set_options(options o, std::error_code &ec) { impl->sslcontext.set_options(o, ec); }
    void context::set_verify_mode(verify_mode v) { impl->sslcontext.set_verify_mode(v); }
    std::error_code context::set_verify_mode(verify_mode v, std::error_code &ec) { impl->sslcontext.set_verify_mode(v, ec); }
    void context::set_verify_depth(int depth) { impl->sslcontext.set_verify_depth(depth); }
    std::error_code context::set_verify_depth(int depth, std::error_code &ec) { impl->sslcontext.set_verify_depth(depth, ec); }
    void context::set_verify_callback(const std::function<bool(bool preverified, X509_STORE_CTX *)> &callback)
    {
        impl->sslcontext.set_verify_callback([callback](bool p, asio::ssl::verify_context &ctx) { return callback(p, ctx.native_handle()); });
    }

    std::error_code context::set_verify_callback(const std::function<bool(bool preverified, X509_STORE_CTX *)> &callback, std::error_code &ec) {}

    void context::load_verify_file(const std::string &filename) {}

    std::error_code context::load_verify_file(const std::string &filename, std::error_code &ec) {}

    void context::add_certificate_authority(const std::vector<unsigned char> &ca) {}

    std::error_code context::add_certificate_authority(const std::vector<unsigned char> &ca, std::error_code &ec) {}

    void context::set_default_verify_paths() {}

    std::error_code context::set_default_verify_paths(std::error_code &ec) {}

    void context::add_verify_path(const std::string &path) {}

    std::error_code context::add_verify_path(const std::string &path, std::error_code &ec) {}

    void context::use_certificate(const std::vector<unsigned char> &certificate, file_format format) {}

    std::error_code context::use_certificate(const std::vector<unsigned char> &certificate, file_format format, std::error_code &ec) {}

    void context::use_certificate_file(const std::string &filename, file_format format) {}

    std::error_code context::use_certificate_file(const std::string &filename, file_format format, std::error_code &ec) {}

    void context::use_certificate_chain(const std::vector<unsigned char> &chain) {}

    std::error_code context::use_certificate_chain(const std::vector<unsigned char> &chain, std::error_code &ec) {}

    void context::use_certificate_chain_file(const std::string &filename) {}

    std::error_code context::use_certificate_chain_file(const std::string &filename, std::error_code &ec) {}

    void context::use_private_key(const std::vector<unsigned char> &private_key, file_format format) {}

    std::error_code context::use_private_key(const std::vector<unsigned char> &private_key, file_format format, std::error_code &ec) {}

    void context::use_private_key_file(const std::string &filename, file_format format) {}

    std::error_code context::use_private_key_file(const std::string &filename, file_format format, std::error_code &ec) {}

    void context::use_rsa_private_key(const std::vector<unsigned char> &private_key, file_format format) {}

    std::error_code context::use_rsa_private_key(const std::vector<unsigned char> &private_key, file_format format, std::error_code &ec) {}

    void context::use_rsa_private_key_file(const std::string &filename, file_format format) {}

    std::error_code context::use_rsa_private_key_file(const std::string &filename, file_format format, std::error_code &ec) {}

    void context::use_tmp_dh(const std::vector<unsigned char> &dh) {}

    std::error_code context::use_tmp_dh(const std::vector<unsigned char> &dh, std::error_code &ec) {}

    void context::use_tmp_dh_file(const std::string &filename) {}

    std::error_code context::use_tmp_dh_file(const std::string &filename, std::error_code &ec) {}

    void context::set_password_callback(std::function<std::string(std::size_t, password_purpose)> &callback) {}

    std::error_code context::set_password_callback(std::function<std::string(std::size_t, password_purpose)> &callback, asio::error_code &ec) {}

} // namespace WS_LITE
} // namespace SL