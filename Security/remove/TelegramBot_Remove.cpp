#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>

bool TelegramBot::removeInstallation()
{
    std::cout << "\nRemoving Telegram bot...\n";

    std::string output;

    int exitCode = -1;

    std::string command =
        "systemctl stop " +
        TELEGRAM_SERVICE +
        " 2>/dev/null || true; "
        "systemctl disable " +
        TELEGRAM_SERVICE +
        " 2>/dev/null || true; "
        "rm -f " +
        shellQuote(TELEGRAM_SERVICE_PATH) +
        "; "
        "systemctl daemon-reload; "
        "rm -rf " +
        shellQuote(TELEGRAM_DIR) +
        "; "
        "rm -rf " +
        shellQuote(TELEGRAM_CODE_BACKUP);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Failed to remove Telegram bot.\n";

        return false;
    }

    std::cout << "Telegram bot removed.\n";

    return true;
}

bool TelegramBot::webRemove()
{
    if (!serviceExists())
    {
        return false;
    }

    return removeInstallation();
}