#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>

bool TelegramBot::stopService()
{
    std::string output;

    int exitCode = -1;

    if (!executeRemote("systemctl stop " + TELEGRAM_SERVICE, output, exitCode, true))
    {
        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    return true;
}

bool TelegramBot::webStop()
{
    if (!serviceExists())
    {
        return false;
    }

    return stopService();
}