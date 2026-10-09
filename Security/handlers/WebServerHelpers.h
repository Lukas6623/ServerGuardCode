#pragma once

#include <string>

inline std::string addOkToJson(
    const std::string& json,
    bool result
)
{
    if (
        !json.empty() &&
        json.back() == '}'
        )
    {
        std::string output = json;

        output.pop_back();

        output += ",\"ok\":";
        output += result ? "true}" : "false}";

        return output;
    }

    return std::string("{\"ok\":") +
        (result ? "true}" : "false}");
}