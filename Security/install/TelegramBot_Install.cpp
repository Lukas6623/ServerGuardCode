#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>
#include <thread>
#include <chrono>

bool TelegramBot::install()
{
    std::cout << "\n[INSTALL] install() WITHOUT TOKEN\n";
    return installInternal(nullptr);
}

bool TelegramBot::install(
    const std::string& token
)
{
    std::cout << "\n[INSTALL] install(token) WITH TOKEN\n";
    return installInternal(&token);
}

bool TelegramBot::installInternal(
    const std::string* webToken
)
{
    std::cout << "\n========================================\n";
    std::cout << "TelegramBot::installInternal()\n";

    if (webToken != nullptr)
    {
        std::cout << "INSTALL MODE: WEB\n";
        std::cout << "Token received from WEB: YES\n";
    }
    else
    {
        std::cout << "INSTALL MODE: CONSOLE\n";
        std::cout << "Token received from WEB: NO\n";
    }

    std::cout << "========================================\n";

    if (!checkRootOrSudo())
    {
        std::cout
            << "\nInstallation stopped.\n";

        return false;
    }

    std::cout
        << "Checking required commands...\n";

    if (!commandExists("systemctl"))
    {
        std::cout
            << "systemctl is not available.\n";

        return false;
    }

    if (!commandExists("base64"))
    {
        std::cout
            << "base64 is not available.\n";

        return false;
    }

    if (!commandExists("curl"))
    {
        std::cout
            << "curl is not available.\n";

        std::cout
            << "It will be installed with Python dependencies.\n";
    }

    if (!commandExists("unzip"))
    {
        std::cout
            << "unzip is not available.\n";

        std::cout
            << "It will be installed with Python dependencies.\n";
    }

    if (!createDirectories())
    {
        return false;
    }

    if (!installPythonDependencies())
    {
        return false;
    }

    if (!downloadBot())
    {
        return false;
    }

    if (!updatePythonLibraries())
    {
        std::cout
            << "\nFailed to install Python libraries required "
            "by Telegram repository.\n";

        return false;
    }

    if (!checkScript())
    {
        std::cout
            << "\nTelegram bot script was not found.\n";

        return false;
    }

    if (!checkPythonSyntax(TELEGRAM_SCRIPT))
    {
        std::cout
            << "\nTelegram bot Python syntax is invalid.\n";

        return false;
    }

    bool configResult = false;

    if (webToken != nullptr)
    {
        configResult =
            createConfig(*webToken);
    }
    else
    {
        configResult =
            createConfig();
    }

    if (!configResult)
    {
        return false;
    }

    if (!serviceExists())
    {
        if (!createSystemdService())
        {
            return false;
        }
    }
    else
    {
        std::cout
            << "\nTelegram systemd service already exists.\n";
    }

    if (!reloadSystemd())
    {
        return false;
    }

    if (!enableService())
    {
        return false;
    }

    if (!startService())
    {
        return false;
    }

    std::cout
        << "\nWaiting for Telegram bot...\n";

    std::this_thread::sleep_for(
        std::chrono::seconds(2)
    );

    std::cout
        << "\nChecking Telegram bot service...\n";

    if (serviceIsActive())
    {
        std::cout << "\n";

        std::cout
            << "============================================\n";

        std::cout
            << "       TELEGRAM BOT ENABLED\n";

        std::cout
            << "============================================\n\n";

        std::cout
            << "Repository: Lukas6623/ServerGuardTelegram\n";

        std::cout
            << "Service: "
            << TELEGRAM_SERVICE
            << "\n";

        std::cout
            << "Status: ACTIVE\n";

        std::cout
            << "Startup: ENABLED\n";

        std::cout
            << "Bot: RUNNING\n";

        std::cout
            << "Python: VIRTUAL ENVIRONMENT\n";

        if (requirementsExists())
        {
            std::cout
                << "Requirements: INSTALLED\n";
        }
        else
        {
            std::cout
                << "Requirements: NOT PRESENT\n";
        }

        std::cout
            << "aiogram: INSTALLED\n";

        return true;
    }

    std::cout
        << "\nTelegram bot failed to start.\n";

    std::cout
        << "\nLast service logs:\n";

    std::cout
        << "--------------------------------------------\n";

    std::string logs;

    int logExitCode = -1;

    executeRemote(
        "journalctl -u "
        + TELEGRAM_SERVICE
        + " -n 50 --no-pager",
        logs,
        logExitCode,
        false
    );

    if (!logs.empty())
    {
        std::cout << logs;
    }

    std::cout
        << "--------------------------------------------\n";

    return false;
}

bool TelegramBot::webInstall()
{
    std::cout << "\n[WEB INSTALL] WITHOUT TOKEN\n";
    return install();
}

bool TelegramBot::webInstall(const std::string& token)
{
    std::cout << "\n[WEB INSTALL] WITH TOKEN\n";
    std::cout << "[WEB INSTALL] Token received: YES\n";
    return install(token);
}