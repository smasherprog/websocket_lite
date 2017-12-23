#pragma once
#include "StringHelpers.h"
#include "WS_Lite.h"
#include <algorithm>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace SL {
namespace WS_LITE {

    constexpr void PlaceValue(std::string_view str, HttpHeader &header)
    {
        if (!str.empty()) {
            if (str[0] == '/') { // url
                header.UrlPart = str;
            }
            else if (str[0] == 'H') {
                if (str == "HTTP/1.1") {
                    header.HttpVersion = HttpVersions::HTTP1_1;
                }
                else if (str == "HTTP/1.0") {
                    header.HttpVersion = HttpVersions::HTTP1_0;
                }
                else if (str == "HTTP/2.0") {
                    header.HttpVersion = HttpVersions::HTTP2_0;
                }
            }
            else if (str[0] == 'G') {
                header.Verb = HttpVerbs::GET;
            }
            else if ((str[0] == 'P') && (str.size() >= 2)) {
                if (str[1] == 'O') {
                    header.Verb = HttpVerbs::POST;
                }
                else if (str[1] == 'U') {
                    header.Verb = HttpVerbs::PUT;
                }
                else if (str[1] == 'A') {
                    header.Verb = HttpVerbs::PATCH;
                }
            }
            else if (str[0] == 'D') {
                header.Verb = HttpVerbs::VDELETE;
            }
            else if (str[0] >= '1' && str[0] <= '5' && str.size() == 3) {
                header.Code = 0;
                for (auto c : str) {
                    header.Code = header.Code * 10 + (c - '0');
                }
            }
        }
    }

    constexpr auto ParseKeyValue(std::string_view line)
    {
        HeaderKeyValue kv;
        auto[key, value] = getline(line, true, ":");
        kv.Key = Trim(key);
        kv.Value = Trim(value);
        return kv;
    }
    constexpr void ParseFirstLine(std::string_view line, HttpHeader &header)
    {
        line = TrimStart(line);
        do {
            auto[foundword, remainingtext] = getline(line, true, " ");
            foundword = Trim(foundword);
            line = remainingtext;
            PlaceValue(foundword, header);
        } while (!line.empty());
    }

    inline void ParseNextLines(std::string_view headerstring, HttpHeader &header)
    {
        do {
            auto[line, remainingtext] = getline(headerstring, true, "\r\n");
            headerstring = remainingtext;
            header.Values.emplace_back(ParseKeyValue(line));
        } while (!headerstring.empty());
    }
    inline SL::WS_LITE::HttpHeader ParseHeader(std::string_view headerstring)
    {
        HttpHeader header;
        auto[line, remainingtext] = getline(headerstring, true, "\r\n");
        ParseFirstLine(line, header);
        ParseNextLines(remainingtext, header);
        return header;
    }
} // namespace WS_LITE
} // namespace SL
