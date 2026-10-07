// ============================================================
// autostart_disable/TelegramBot_DisableAutostart.cpp
//
// Категория: ОТКЛЮЧЕНИЕ автозапуска бота при старте системы.
//
// Содержит:
//   - TelegramBot::disableService()  — systemctl disable сервиса
//   - TelegramBot::webDisable()      — web-обёртка
// ============================================================

#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>


// ============================================================
// DISABLE
// ============================================================

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


// ============================================================
// WEB API - DISABLE
// ============================================================

bool TelegramBot::webDisable()
{
    if (!serviceExists())
    {
        return false;
    }

    return disableService();
}
