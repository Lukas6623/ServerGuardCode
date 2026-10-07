// ============================================================
// update/TelegramBot_Update.cpp
//
// Категория: ОБНОВЛЕНИЕ бота.
//
// Содержит:
//   - TelegramBot::updateBot()   — полное обновление GitHub-репозитория
//                                  бота с бэкапом и автооткатом при ошибке
//   - TelegramBot::webUpdate()   — web-обёртка для updateBot()
//
// Использует общие хелперы из TelegramBot.cpp (downloadRepositoryArchive,
// extractRepository, validateRepository, installRepositoryFiles,
// backupTelegramCode, clearTelegramCode, restoreTelegramCode,
// updatePythonLibraries, checkPythonSyntax, startService, showUpdateLogs
// и т.д.), а также stopService()/restartService() из соседних папок.
// ============================================================

#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>
#include <thread>
#include <chrono>


// ============================================================
// UPDATE BOT
// ============================================================

bool TelegramBot::updateBot()
{
    std::cout << "\n";

    std::cout << "============================================\n";

    std::cout << "          SERVERGUARD TELEGRAM UPDATE\n";

    std::cout << "============================================\n\n";


    // ========================================================
    // ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        std::cout << "\nUpdate stopped.\n";

        return false;
    }


    // ========================================================
    // CURL
    // ========================================================

    if (!commandExists("curl"))
    {
        std::cout << "curl is not installed.\n";

        std::cout << "Installing curl...\n";


        std::string output;

        int exitCode = -1;


        if (!executeRemote(
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y curl",
            output,
            exitCode,
            true
        ))
        {
            std::cout << "Cannot install curl.\n";

            if (!output.empty())
            {
                std::cout << output << "\n";
            }

            return false;
        }
    }


    // ========================================================
    // UNZIP
    // ========================================================

    if (!ensureUnzip())
    {
        return false;
    }


    // ========================================================
    // CHECK INSTALLATION
    // ========================================================

    if (!serviceExists())
    {
        std::cout << "\nTelegram bot is not installed.\n";

        std::cout << "Install the bot first.\n";

        return false;
    }


    if (!checkScript())
    {
        std::cout << "\nTelegram bot script does not exist.\n";

        return false;
    }


    // ========================================================
    // CHECK VENV
    // ========================================================

    std::string output;

    int exitCode = -1;


    std::string python = TELEGRAM_VENV + "/bin/python";


    if (!executeRemote("test -x " + shellQuote(python), output, exitCode, false))
    {
        std::cout << "\nTelegram virtual environment is missing.\n";

        std::cout << "Run Install / configure bot first.\n";

        return false;
    }


    // ========================================================
    // DIRECTORIES
    // ========================================================

    if (!createDirectories())
    {
        return false;
    }


    // ========================================================
    // CHECK CURRENT SERVICE
    // ========================================================

    bool wasActive = serviceIsActive();


    if (wasActive)
    {
        std::cout << "\nStopping Telegram bot before update...\n";


        if (!stopService())
        {
            std::cout << "Cannot stop Telegram bot.\n";

            return false;
        }
    }
    else
    {
        std::cout << "\nTelegram bot is currently inactive.\n";
    }


    // ========================================================
    // PREPARE TEMPORARY UPDATE
    // ========================================================

    executeRemote(
        "rm -rf " +
        shellQuote(TELEGRAM_UPDATE_DIR) +
        " " +
        shellQuote(TELEGRAM_UPDATE_ZIP),
        output,
        exitCode,
        true
    );


    // ========================================================
    // DOWNLOAD COMPLETE REPOSITORY
    // ========================================================

    if (!downloadRepositoryArchive(TELEGRAM_UPDATE_ZIP))
    {
        std::cout << "\nNew Telegram repository could not be downloaded.\n";

        if (wasActive)
        {
            startService();
        }

        return false;
    }


    // ========================================================
    // EXTRACT COMPLETE REPOSITORY
    // ========================================================

    std::string repositoryRoot;


    if (!extractRepository(TELEGRAM_UPDATE_ZIP, TELEGRAM_UPDATE_DIR, repositoryRoot))
    {
        std::cout << "\nNew Telegram repository could not be extracted.\n";


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // VALIDATE COMPLETE REPOSITORY
    // ========================================================

    if (!validateRepository(repositoryRoot))
    {
        std::cout << "\nNew Telegram repository failed validation.\n";

        std::cout << "Existing bot was NOT replaced.\n";


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // BACKUP CURRENT BOT
    // ========================================================

    if (!backupTelegramCode())
    {
        std::cout << "\nBackup failed.\n";

        std::cout << "Existing bot was NOT replaced.\n";


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // REMOVE OLD CODE
    // ========================================================

    if (!clearTelegramCode())
    {
        std::cout << "\nCannot remove old Telegram bot code.\n";


        restoreTelegramCode();


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // INSTALL COMPLETE NEW REPOSITORY
    // ========================================================

    std::cout << "\nInstalling new Telegram repository...\n";


    if (!installRepositoryFiles(repositoryRoot))
    {
        std::cout << "\nCannot install new Telegram repository.\n";


        restoreTelegramCode();


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // FINAL MAIN SCRIPT CHECK
    // ========================================================

    if (!checkScript())
    {
        std::cout << "\nNew repository does not contain telegram_bot.py.\n";

        std::cout << "Restoring previous version...\n";


        restoreTelegramCode();


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // UPDATE PYTHON LIBRARIES
    // ========================================================

    if (!updatePythonLibraries())
    {
        std::cout << "\nPython library update failed.\n";

        std::cout << "Restoring previous Telegram bot...\n";


        restoreTelegramCode();


        // Try to restore dependencies from previous
        // requirements.txt if it existed in the backup.

        std::string oldRequirements = TELEGRAM_CODE_BACKUP + "/requirements.txt";


        output.clear();

        exitCode = -1;


        if (executeRemote(
            "test -s " + shellQuote(oldRequirements),
            output,
            exitCode,
            false
        ))
        {
            std::cout << "Restoring previous Python requirements...\n";


            executeRemote(
                shellQuote(python) +
                " -m pip install --upgrade -r " +
                shellQuote(oldRequirements),
                output,
                exitCode,
                true
            );
        }


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // FINAL PYTHON SYNTAX CHECK
    // ========================================================

    std::cout << "\nPerforming final Python syntax check...\n";


    if (!checkPythonSyntax(TELEGRAM_SCRIPT))
    {
        std::cout << "\nFinal syntax check failed.\n";

        std::cout << "Restoring previous Telegram bot...\n";


        restoreTelegramCode();


        // Restore old requirements if possible.

        std::string oldRequirements = TELEGRAM_CODE_BACKUP + "/requirements.txt";


        output.clear();

        exitCode = -1;


        if (executeRemote(
            "test -s " + shellQuote(oldRequirements),
            output,
            exitCode,
            false
        ))
        {
            executeRemote(
                shellQuote(python) +
                " -m pip install --upgrade -r " +
                shellQuote(oldRequirements),
                output,
                exitCode,
                true
            );
        }


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // RELOAD SYSTEMD
    // ========================================================

    if (!reloadSystemd())
    {
        std::cout << "\nWarning: systemd reload failed.\n";
    }


    // ========================================================
    // START UPDATED BOT
    // ========================================================

    std::cout << "\nStarting updated Telegram bot...\n";


    if (!startService())
    {
        std::cout << "\nUpdated Telegram bot failed to start.\n";

        std::cout << "Restoring previous version...\n";


        restoreTelegramCode();


        // Restore old dependencies.

        std::string oldRequirements = TELEGRAM_CODE_BACKUP + "/requirements.txt";


        output.clear();

        exitCode = -1;


        if (executeRemote(
            "test -s " + shellQuote(oldRequirements),
            output,
            exitCode,
            false
        ))
        {
            executeRemote(
                shellQuote(python) +
                " -m pip install --upgrade -r " +
                shellQuote(oldRequirements),
                output,
                exitCode,
                true
            );
        }


        reloadSystemd();


        std::cout << "Starting previous version...\n";


        startService();


        std::this_thread::sleep_for(std::chrono::seconds(1));


        if (serviceIsActive())
        {
            std::cout << "Previous Telegram bot version restored successfully.\n";
        }
        else
        {
            std::cout
                << "WARNING: Previous bot version was restored, "
                "but service is not active.\n";
        }


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        showUpdateLogs();

        return false;
    }


    // ========================================================
    // WAIT
    // ========================================================

    std::cout << "\nWaiting for Telegram bot...\n";


    std::this_thread::sleep_for(std::chrono::seconds(2));


    // ========================================================
    // CHECK
    // ========================================================

    if (!serviceIsActive())
    {
        std::cout << "\nUpdated Telegram bot is not active.\n";

        std::cout << "Restoring previous version...\n";


        restoreTelegramCode();


        // Restore old Python requirements.

        std::string oldRequirements = TELEGRAM_CODE_BACKUP + "/requirements.txt";


        output.clear();

        exitCode = -1;


        if (executeRemote(
            "test -s " + shellQuote(oldRequirements),
            output,
            exitCode,
            false
        ))
        {
            executeRemote(
                shellQuote(python) +
                " -m pip install --upgrade -r " +
                shellQuote(oldRequirements),
                output,
                exitCode,
                true
            );
        }


        reloadSystemd();


        startService();


        std::this_thread::sleep_for(std::chrono::seconds(1));


        if (serviceIsActive())
        {
            std::cout << "Previous Telegram bot version restored.\n";
        }
        else
        {
            std::cout << "WARNING: Telegram bot is still inactive.\n";
        }


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        showUpdateLogs();

        return false;
    }


    // ========================================================
    // CLEAN TEMPORARY FILES
    // ========================================================

    executeRemote(
        "rm -rf " +
        shellQuote(TELEGRAM_UPDATE_DIR) +
        " " +
        shellQuote(TELEGRAM_UPDATE_ZIP),
        output,
        exitCode,
        true
    );


    // ========================================================
    // SUCCESS
    // ========================================================

    std::cout << "\n";

    std::cout << "============================================\n";

    std::cout << "       TELEGRAM BOT UPDATED SUCCESSFULLY\n";

    std::cout << "============================================\n\n";


    std::cout << "Repository: Lukas6623/ServerGuardTelegram\n";

    std::cout << "Repository files: UPDATED\n";

    std::cout << "Python libraries: UPDATED\n";

    std::cout << "Configuration: PRESERVED\n";

    std::cout << "Verification data: PRESERVED\n";

    std::cout << "Owner data: PRESERVED\n";

    std::cout << "Queue: PRESERVED\n";

    std::cout << "Virtual environment: PRESERVED\n";

    std::cout << "Service: ACTIVE\n";


    std::cout << "\nBackup:\n" << TELEGRAM_CODE_BACKUP << "\n";


    return true;
}


// ============================================================
// WEB API - UPDATE
// ============================================================

bool TelegramBot::webUpdate()
{
    return updateBot();
}
