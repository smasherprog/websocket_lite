#pragma once

#include "cppcodec/base64_rfc4648.hpp"
#include "internal/SHA.h"

#include <unordered_map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <memory>
#include <random>
#include <fstream>

namespace SL {
    namespace WS_LITE {
        inline std::ifstream::pos_type filesize(const std::string& filename)
        {
            std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
            return in.tellg();
        }

        template <typename T>
        T swap_endian(T u)
        {
            static_assert (CHAR_BIT == 8, "CHAR_BIT != 8");
            union
            {
                T u;
                unsigned char u8[sizeof(T)];
            } source, dest;
            source.u = u;
            for (size_t k = 0; k < sizeof(T); k++)
                dest.u8[k] = source.u8[sizeof(T) - k - 1];

            return dest.u;
        }
        inline std::string url_decode(const std::string& in)
        {
            std::string out;
            out.reserve(in.size());
            for (std::size_t i = 0; i < in.size(); ++i)
            {
                if (in[i] == '%')
                {
                    if (i + 3 <= in.size())
                    {
                        int value = 0;
                        std::istringstream is(in.substr(i + 1, 2));
                        if (is >> std::hex >> value)
                        {
                            out += static_cast<char>(value);
                            i += 2;
                        }
                        else
                        {
                            return std::string("/");
                        }
                    }
                    else
                    {
                        return std::string("/");
                    }
                }
                else if (in[i] == '+')
                {
                    out += ' ';
                }
                else
                {
                    out += in[i];
                }
            }
            return out;
        }

        inline bool Parse_Handshake(std::string defaultheaderversion, std::istream& stream, std::unordered_map<std::string, std::string>& header)
        {
            std::string line;
            std::getline(stream, line);
            size_t method_end;
            if ((method_end = line.find(' ')) != std::string::npos) {
                size_t path_end;
                if ((path_end = line.find(' ', method_end + 1)) != std::string::npos) {
                    header[HTTP_METHOD] = line.substr(0, method_end);
                    header[HTTP_PATH] = url_decode(line.substr(method_end + 1, path_end - method_end - 1));
                    if ((path_end + 6) < line.size())
                        header[HTTP_VERSION] = line.substr(path_end + 6, line.size() - (path_end + 6) - 1);
                    else
                        header[HTTP_VERSION] = defaultheaderversion;

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
            }
            return true;
        }

        const std::string ws_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        inline bool Generate_Handshake(std::unordered_map<std::string, std::string>& header, std::ostream & stream)
        {
            auto header_it = header.find(HTTP_SECWEBSOCKETKEY);
            if (header_it == header.end())
                return false;

            auto sha1 = SHA1(header_it->second + ws_magic_string);
            stream << "HTTP/1.1 101 Web Socket Protocol Handshake" << HTTP_ENDLINE;
            stream << "Upgrade: websocket" << HTTP_ENDLINE;
            stream << "Connection: Upgrade" << HTTP_ENDLINE;

            stream << HTTP_SECWEBSOCKETACCEPT << HTTP_KEYVALUEDELIM << cppcodec::base64_rfc4648::encode(sha1) << HTTP_ENDLINE << HTTP_ENDLINE;
            return true;
        }
        inline std::string Generate_Handshake(const std::string& host_addr, std::ostream & request) {

            request << "GET /rdpenpoint/ HTTP/1.1" << HTTP_ENDLINE;
            request << HTTP_HOST << HTTP_KEYVALUEDELIM << host_addr << HTTP_ENDLINE;
            request << "Upgrade: websocket" << HTTP_ENDLINE;
            request << "Connection: Upgrade" << HTTP_ENDLINE;

            //Make random 16-byte nonce
            std::string nonce;
            nonce.resize(16);
            std::uniform_int_distribution<unsigned int> dist(0, 255);
            std::random_device rd;
            for (int c = 0; c < 16; c++) {
                nonce[c] = static_cast<unsigned char>(dist(rd));
            }

            auto nonce_base64 = cppcodec::base64_rfc4648::encode<std::string>(nonce);
            request << HTTP_SECWEBSOCKETKEY << HTTP_KEYVALUEDELIM << nonce_base64 << HTTP_ENDLINE;
            request << "Sec-WebSocket-Version: 13" << HTTP_ENDLINE << HTTP_ENDLINE;
            return SHA1(nonce_base64 + ws_magic_string);
        }

    }
}