#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>

bool TelegramBot::enableService()
{
    std::cout << "\nEnabling Telegram automatic startup...\n";

    std::string output;

    int exitCode = -1;

    if (!executeRemote("systemctl enable " + TELEGRAM_SERVICE, output, exitCode, true))
    {
        std::cout << "Failed to enable Telegram service.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    std::cout << "Telegram automatic startup enabled.\n";

    return true;
}