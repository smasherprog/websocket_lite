#pragma once

#include <string>
#include <string_view>
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

    constexpr auto getline(std::string_view line, bool consume_delimiter, std::string_view delimiter)
    {
        size_t foundindex = line.find(delimiter);
        if (foundindex == std::string_view::npos) {
            return std::make_tuple(line, std::string_view(line.data() + line.size(), 0));
        }
        else {
            auto remainingstart = line.data() + foundindex + (consume_delimiter ? delimiter.size() : 0);
            auto remainingsize = (line.data() + line.size()) - remainingstart;
            return std::make_tuple(std::string_view(line.data(), foundindex), std::string_view(remainingstart, remainingsize));
        }
    }

} // namespace WS_LITE
} // namespace SL
