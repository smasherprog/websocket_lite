#pragma once
#include "Logging.h"
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>

#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <math.h>
#include <zlib.h>

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

    /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-------+-+-------------+-------------------------------+
    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    | |1|2|3|       |K|             |                               |
    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    |     Extended payload length continued, if payload len == 127  |
    + - - - - - - - - - - - - - - - +-------------------------------+
    |                               |Masking-key, if MASK set to 1  |
    +-------------------------------+-------------------------------+
    | Masking-key (continued)       |          Payload data         |
    +-------------------------------- - - - - - - - - - - - - - - - +
    :                     Payload data continued ...                :
    + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
    |                     Payload data continued ...                |
    +---------------------------------------------------------------+
    */
    inline bool getFin(unsigned char *frame) { return frame[0] & 128; }
    inline void setFin(unsigned char *frame, unsigned char val) { frame[0] = (val & 128) | (~128 & frame[0]); }

    inline bool getMask(unsigned char *frame) { return frame[1] & 128; }
    inline void setMask(unsigned char *frame, unsigned char val) { frame[1] = (val & 128) | (~128 & frame[1]); }

    inline unsigned char getpayloadLength1(unsigned char *frame) { return frame[1] & 127; }
    inline unsigned short getpayloadLength2(unsigned char *frame) { return *reinterpret_cast<unsigned short *>(frame + 2); }
    inline unsigned long long int getpayloadLength8(unsigned char *frame) { return *reinterpret_cast<unsigned long long int *>(frame + 2); }

    inline void setpayloadLength1(unsigned char *frame, unsigned char val) { frame[1] = (val & 127) | (~127 & frame[1]); }
    inline void setpayloadLength2(unsigned char *frame, unsigned short val) { *reinterpret_cast<unsigned short *>(frame + 2) = val; }
    inline void setpayloadLength8(unsigned char *frame, unsigned long long int val) { *reinterpret_cast<unsigned long long int *>(frame + 2) = val; }

    inline unsigned char getOpCode(unsigned char *frame) { return *frame & 15; }
    inline void setOpCode(unsigned char *frame, unsigned char val) { frame[0] = (val & 15) | (~15 & frame[0]); }

    inline bool getrsv3(unsigned char *frame) { return *frame & 16; }
    inline bool getrsv2(unsigned char *frame) { return *frame & 32; }
    // compressed?
    inline bool getrsv1(unsigned char *frame) { return *frame & 64; }

    inline void setrsv3(unsigned char *frame, unsigned char val) { frame[0] = (val & 16) | (~16 & frame[0]); }
    inline void setrsv2(unsigned char *frame, unsigned char val) { frame[0] = (val & 32) | (~32 & frame[0]); }
    inline void setrsv1(unsigned char *frame, unsigned char val) { frame[0] = (val & 64) | (~64 & frame[0]); }

    constexpr bool DidPassMaskRequirement(unsigned char *h, bool isServer)
    {
        if (isServer) {
            return getMask(h);
        }
        else {
            return !getMask(h);
        }
    }

    constexpr size_t AdditionalBodyBytesToRead(bool isServer)
    {
        if (isServer) {
            return 4;
        }
        else {
            return 0;
        }
    }
    constexpr void set_MaskBitForSending(unsigned char *frame, bool isServer)
    {
        if (isServer) {
            setMask(frame, 0x00);
        }
        else {
            setMask(frame, 0xff);
        }
    }

    template <class T> std::string get_address(T &_socket)
    {
        std::error_code ec;
        auto rt(_socket.lowest_layer().remote_endpoint(ec));
        if (!ec)
            return rt.address().to_string();
        else
            return "";
    }
    template <class T> unsigned short get_port(T &_socket)
    {
        std::error_code ec;
        auto rt(_socket.lowest_layer().remote_endpoint(ec));
        if (!ec)
            return rt.port();
        else
            return static_cast<unsigned short>(-1);
    }
    template <class T> bool is_v4(T &_socket)
    {
        std::error_code ec;
        auto rt(_socket.lowest_layer().remote_endpoint(ec));
        if (!ec)
            return rt.address().is_v4();
        else
            return true;
    }
    template <class T> bool is_v6(T &_socket)
    {
        std::error_code ec;
        auto rt(_socket.lowest_layer().remote_endpoint(ec));
        if (!ec)
            return rt.address().is_v6();
        else
            return true;
    }
    template <class T> bool is_loopback(T &_socket)
    {
        std::error_code ec;
        auto rt(_socket.lowest_layer().remote_endpoint(ec));
        if (!ec)
            return rt.address().is_loopback();
        else
            return true;
    }
    template <class type> void SHA1(const type &input, type &hash)
    {
        SHA_CTX context;
        SHA1_Init(&context);
        SHA1_Update(&context, &input[0], input.size());

        hash.resize(160 / 8);
        SHA1_Final((unsigned char *)&hash[0], &context);
    }
    template <class type> type SHA1(const type &input)
    {
        type hash;
        SHA1(input, hash);
        return hash;
    }

    template <class type> type Base64encode(const type &ascii)
    {
        BIO *bio, *b64;
        BUF_MEM *bptr;

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_new(BIO_s_mem());
        BIO_push(b64, bio);
        BIO_get_mem_ptr(b64, &bptr);

        // Write directly to base64-buffer to avoid copy
        int base64_length = static_cast<int>(round(4 * ceil((double)ascii.size() / 3.0)));
        type base64;
        base64.resize(base64_length);
        bptr->length = 0;
        bptr->max = base64_length + 1;
        bptr->data = (char *)&base64[0];

        BIO_write(b64, &ascii[0], static_cast<int>(ascii.size()));
        BIO_flush(b64);

        // To keep &base64[0] through BIO_free_all(b64)
        bptr->length = 0;
        bptr->max = 0;
        bptr->data = nullptr;

        BIO_free_all(b64);
        return base64;
    }
    template <class type> void Base64decode(const type &base64, type &ascii)
    {
        // Resize ascii, however, the size is a up to two bytes too large.
        ascii.resize((6 * base64.size()) / 8);
        BIO *b64, *bio;

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_new_mem_buf((char *)&base64[0], static_cast<int>(base64.size()));
        bio = BIO_push(b64, bio);

        int decoded_length = BIO_read(bio, &ascii[0], static_cast<int>(ascii.size()));
        ascii.resize(decoded_length);

        BIO_free_all(b64);
    }
    template <class type> type Base64decode(const type &base64)
    {
        type ascii;
        Base64decode(base64, ascii);
        return ascii;
    }

    template <typename T> T ntoh(T u)
    {
        static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");
        union {
            T u;
            unsigned char u8[sizeof(T)];
        } source, dest;
        source.u = u;
        for (size_t k = 0; k < sizeof(T); k++)
            dest.u8[k] = source.u8[sizeof(T) - k - 1];

        return dest.u;
    }
    template <typename T> T hton(T u)
    {
        static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");
        union {
            T u;
            unsigned char u8[sizeof(T)];
        } source, dest;
        source.u = u;
        for (size_t k = 0; k < sizeof(T); k++)
            dest.u8[sizeof(T) - k - 1] = source.u8[k];

        return dest.u;
    }

    const std::string ws_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const int LARGE_BUFFER_SIZE = 300 * 1024;

    inline std::string url_decode(const std::string &in)
    {
        std::string out;
        out.reserve(in.size());
        for (std::size_t i = 0; i < in.size(); ++i) {
            if (in[i] == '%') {
                if (i + 3 <= in.size()) {
                    int value = 0;
                    std::istringstream is(in.substr(i + 1, 2));
                    if (is >> std::hex >> value) {
                        out += static_cast<char>(value);
                        i += 2;
                    }
                    else {
                        return std::string("/");
                    }
                }
                else {
                    return std::string("/");
                }
            }
            else if (in[i] == '+') {
                out += ' ';
            }
            else {
                out += in[i];
            }
        }
        return out;
    }

    inline bool Parse_ServerHandshake(std::istream &stream, std::unordered_map<std::string, std::string> &header)
    {
        std::string line;
        std::getline(stream, line);

        size_t path_end;
        if ((path_end = line.find(' ')) != std::string::npos) {

            if (path_end == 8)
                header[HTTP_VERSION] = line.substr(path_end - 3, 3);
            else {
                SL_WS_LITE_LOG(Logging_Levels::INFO_log_level, "Parse_ServerHandshake failed due to no http version in header");
                return false;
            }
            if (line.size() > path_end + 4) {
                header[HTTP_METHOD] = line.substr(path_end + 1, line.size() - path_end - 1);
            }

            getline(stream, line);
            size_t param_end;
            while ((param_end = line.find(':')) != std::string::npos) {
                size_t value_start = param_end + 1;
                if ((value_start) < line.size()) {
                    if (line[value_start] == ' ')
                        value_start++;
                    if (value_start < line.size())
                        header.insert(std::make_pair(line.substr(0, param_end), line.substr(value_start, line.size() - value_start - 1)));
                }

                getline(stream, line);
            }
        }
        return true;
    }

    inline bool Parse_ClientHandshake(std::istream &stream, std::unordered_map<std::string, std::string> &header) { return true; }

    inline bool Generate_Handshake(std::unordered_map<std::string, std::string> &header, std::ostream &handshake)
    {
        auto header_it = header.find(HTTP_SECWEBSOCKETKEY);
        if (header_it == header.end()) {
            return false;
        }
        auto sha1 = SHA1(header_it->second + ws_magic_string);
        handshake << "HTTP/1.1 101 Web Socket Protocol Handshake" << HTTP_ENDLINE;
        handshake << "Upgrade: websocket" << HTTP_ENDLINE;
        handshake << "Connection: Upgrade" << HTTP_ENDLINE;
        header_it = header.find(HTTP_SECWEBSOCKETEXTENSIONS);
        /*      if (header_it != header.end() && header_it->second.find(PERMESSAGEDEFLATE) != std::string::npos) {
        handshake << HTTP_SECWEBSOCKETEXTENSIONS << HTTP_KEYVALUEDELIM << PERMESSAGEDEFLATE << HTTP_ENDLINE;
        }
        else {
        handshake << HTTP_SECWEBSOCKETEXTENSIONS << HTTP_KEYVALUEDELIM << HTTP_ENDLINE;
        }*/
        handshake << HTTP_SECWEBSOCKETACCEPT << HTTP_KEYVALUEDELIM << Base64encode(sha1) << HTTP_ENDLINE << HTTP_ENDLINE;

        return true;
    }
    bool isValidUtf8(unsigned char *s, size_t length);
    char *ZlibInflate(char *data, size_t &length, size_t maxPayload, std::string &dynamicInflationBuffer, z_stream &inflationStream,
                      char *inflationBuffer);

} // namespace WS_LITE
} // namespace SL