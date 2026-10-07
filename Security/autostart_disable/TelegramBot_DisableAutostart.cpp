#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>

bool TelegramBot::disableService()
{
    std::string output;

    int exitCode = -1;

    if (!executeRemote("systemctl disable " + TELEGRAM_SERVICE, output, exitCode, true))
    {
        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    return true;
}

bool TelegramBot::webDisable()
{
    if (!serviceExists())
    {
        return false;
    }

    return disableService();
}