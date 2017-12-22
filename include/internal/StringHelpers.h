#pragma once

#include <string>
#include <tuple>

namespace SL {
namespace WS_LITE {

    constexpr auto TrimStart(std::string_view line)
    { // this will trim any white space
        if (line.empty()) {
            return line;
        }
        size_t wordstart = 0;
        for (; wordstart < line.size(); wordstart++) {
            if (line[wordstart] != ' ') {
                break;
            }
        }
        return std::string_view(line.data() + wordstart, line.size() - wordstart);
    }
    constexpr auto TrimEnd(std::string_view line)
    { // this will trim any white space
        if (line.empty()) {
            return line;
        }
        size_t wordend = line.size();
        while (true) {
            if (line[wordend - 1] != ' ' || wordend - 1 == 0) {
                break;
            }
            wordend -= 1;
        }
        return std::string_view(line.data(), wordend);
    }
    constexpr auto Trim(std::string_view str) { return TrimEnd(TrimStart(str)); }
    constexpr auto getline(std::string_view line, bool consume_delimiter, char delimiter)
    {
        size_t wordend = 0;
        for (; wordend < line.size(); wordend++) {
            if (line[wordend] == delimiter) {
                break;
            }
        }
        // return the found data, plus the remaining data

        if (wordend == line.size()) {
            return std::make_tuple(line, std::string_view(line.data() + line.size(), 0));
        }
        else {

            auto remainingstart = line.data() + wordend + (consume_delimiter ? 1 : 0);
            auto remainingsize = (line.data() + line.size()) - remainingstart;
            return std::make_tuple(std::string_view(line.data(), wordend), std::string_view(remainingstart, remainingsize));
        }
    }
} // namespace WS_LITE
} // namespace SL
