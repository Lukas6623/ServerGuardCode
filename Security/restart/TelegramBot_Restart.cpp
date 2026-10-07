#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>

bool TelegramBot::restartService()
{
    std::cout << "\nRestarting Telegram bot...\n";

    std::string output;

    int exitCode = -1;

    if (!executeRemote("systemctl restart " + TELEGRAM_SERVICE, output, exitCode, true))
    {
        std::cout << "Failed to restart Telegram bot.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    std::cout << "Telegram bot restarted.\n";

    return true;
}

bool TelegramBot::webRestart()
{
    if (!serviceExists())
    {
        return false;
    }

    return restartService();
}