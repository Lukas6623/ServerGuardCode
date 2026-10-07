#pragma once

#include <string>

inline const std::string TELEGRAM_DIR =
"/opt/serverguard/telegram";

inline const std::string TELEGRAM_SCRIPT =
"/opt/serverguard/telegram/telegram_bot.py";

inline const std::string TELEGRAM_CONFIG =
"/opt/serverguard/telegram/telegram.conf";

inline const std::string TELEGRAM_VERIFICATION =
"/opt/serverguard/telegram/verification.json";

inline const std::string TELEGRAM_OWNER =
"/opt/serverguard/telegram/owner.json";

inline const std::string TELEGRAM_QUEUE =
"/opt/serverguard/telegram/queue";

inline const std::string TELEGRAM_VENV =
"/opt/serverguard/telegram/venv";

inline const std::string TELEGRAM_SERVICE =
"serverguard-telegram.service";

inline const std::string TELEGRAM_SERVICE_PATH =
"/etc/systemd/system/serverguard-telegram.service";

inline const std::string GITHUB_TELEGRAM_REPOSITORY_ZIP =
"https://github.com/"
"Lukas6623/ServerGuardTelegram/"
"archive/refs/heads/main.zip";

inline const std::string TELEGRAM_UPDATE_DIR =
"/opt/serverguard/telegram/.repository_update";

inline const std::string TELEGRAM_UPDATE_ZIP =
"/opt/serverguard/telegram/.repository_update.zip";

inline const std::string TELEGRAM_CODE_BACKUP =
"/opt/serverguard/telegram_backup";

inline std::string shellQuote(const std::string& value)
{
    std::string result = "'";

    for (char c : value)
    {
        if (c == '\'')
        {
            result += "'\\''";
        }
        else
        {
            result += c;
        }
    }

    result += "'";

    return result;
}

inline std::string base64Encode(const std::string& input)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string output;

    int val = 0;
    int valb = -6;

    for (unsigned char c : input)
    {
        val = (val << 8) + c;
        valb += 8;

        while (valb >= 0)
        {
            output.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6)
    {
        output.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (output.size() % 4)
    {
        output.push_back('=');
    }

    return output;
}

inline std::string trim(const std::string& value)
{
    std::size_t start = 0;

    while (
        start < value.size() &&
        (
            value[start] == ' ' ||
            value[start] == '\n' ||
            value[start] == '\r' ||
            value[start] == '\t'
            )
        )
    {
        ++start;
    }

    std::size_t end = value.size();

    while (
        end > start &&
        (
            value[end - 1] == ' ' ||
            value[end - 1] == '\n' ||
            value[end - 1] == '\r' ||
            value[end - 1] == '\t'
            )
        )
    {
        --end;
    }

    return value.substr(start, end - start);
}