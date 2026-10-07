// ============================================================
// install/TelegramBot_Install.cpp
//
// Категория: УСТАНОВКА бота.
//
// Содержит:
//   - TelegramBot::install()       — полная установка/конфигурация бота
//   - TelegramBot::webInstall()    — web-обёртка для install()
//
// Использует общие хелперы из TelegramBot.cpp (checkRootOrSudo,
// createDirectories, installPythonDependencies, downloadBot,
// checkScript, checkPythonSyntax, createConfig, createSystemdService,
// reloadSystemd, enableService, startService, serviceIsActive и т.д.)
// ============================================================

#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>
#include <thread>
#include <chrono>


// ============================================================
// INSTALL / CONFIGURE
// ============================================================

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


    // ========================================================
    // ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        std::cout
            << "\nInstallation stopped.\n";

        return false;
    }


    // ========================================================
    // REQUIRED COMMANDS
    // ========================================================

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


    // ========================================================
    // DIRECTORIES
    // ========================================================

    if (!createDirectories())
    {
        return false;
    }


    // ========================================================
    // PYTHON / VENV / AIOGRAM
    // ========================================================

    if (!installPythonDependencies())
    {
        return false;
    }


    // ========================================================
    // COMPLETE TELEGRAM REPOSITORY
    // ========================================================

    if (!downloadBot())
    {
        return false;
    }


    // ========================================================
    // PYTHON LIBRARIES FROM REPOSITORY
    // ========================================================

    if (!updatePythonLibraries())
    {
        std::cout
            << "\nFailed to install Python libraries required "
            "by Telegram repository.\n";

        return false;
    }


    // ========================================================
    // FINAL SCRIPT CHECK
    // ========================================================

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


    // ========================================================
    // CONFIG
    // ========================================================

    bool configResult = false;


    if (webToken != nullptr)
    {
        // ====================================================
        // WEB INSTALLATION
        // ====================================================

        configResult =
            createConfig(*webToken);
    }
    else
    {
        // ====================================================
        // CONSOLE INSTALLATION
        // ====================================================

        configResult =
            createConfig();
    }


    if (!configResult)
    {
        return false;
    }


    // ========================================================
    // SERVICE
    // ========================================================

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


    // ========================================================
    // RELOAD
    // ========================================================

    if (!reloadSystemd())
    {
        return false;
    }


    // ========================================================
    // ENABLE
    // ========================================================

    if (!enableService())
    {
        return false;
    }


    // ========================================================
    // START
    // ========================================================

    if (!startService())
    {
        return false;
    }


    // ========================================================
    // WAIT
    // ========================================================

    std::cout
        << "\nWaiting for Telegram bot...\n";


    std::this_thread::sleep_for(
        std::chrono::seconds(2)
    );


    // ========================================================
    // CHECK
    // ========================================================

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


    // ========================================================
    // FAILED
    // ========================================================

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


// ============================================================
// WEB API - INSTALL
// ============================================================

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