#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>
#include <sstream>
#include <random>
#include <ctime>

std::string TelegramBot::generateRandomCode()
{
    std::random_device rd;

    std::mt19937 generator(rd());

    std::uniform_int_distribution<int> distribution(100000, 999999);

    return std::to_string(distribution(generator));
}

bool TelegramBot::generateVerificationCode()
{
    if (!serviceExists())
    {
        std::cout << "\nTelegram bot is not installed.\n";

        return false;
    }

    std::string code = generateRandomCode();

    long long now = static_cast<long long>(std::time(nullptr));

    long long expires = now + 300;

    std::ostringstream json;

    json
        << "{\n"
        << "    \"code\": \""
        << code
        << "\",\n"
        << "    \"created_at\": "
        << now
        << ",\n"
        << "    \"expires_at\": "
        << expires
        << "\n"
        << "}\n";

    std::string encoded = base64Encode(json.str());

    std::string command =
        "echo " +
        shellQuote(encoded) +
        " | base64 -d > " +
        shellQuote(TELEGRAM_VERIFICATION) +
        " && "
        "chmod 600 " +
        shellQuote(TELEGRAM_VERIFICATION) +
        " && "
        "chown root:root " +
        shellQuote(TELEGRAM_VERIFICATION);

    std::string output;

    int exitCode = -1;

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create verification file.\n";

        return false;
    }

    std::cout << "\n";

    std::cout << "============================================\n";

    std::cout << "        TELEGRAM VERIFICATION\n";

    std::cout << "============================================\n\n";

    std::cout << "Verification code: " << code << "\n\n";

    std::cout << "Valid for: 5 minutes\n\n";

    std::cout << "Open your ServerGuard Telegram bot and send:\n\n";

    std::cout << "/start " << code << "\n\n";

    std::cout << "============================================\n";

    return true;
}

bool TelegramBot::generateCode()
{
    return generateVerificationCode();
}

bool TelegramBot::webGenerateCode()
{
    return generateCode();
}