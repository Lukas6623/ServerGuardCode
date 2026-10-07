// ============================================================
// stop/TelegramBot_Stop.cpp
//
// Категория: ОСТАНОВКА бота.
//
// Содержит:
//   - TelegramBot::stopService()  — systemctl stop сервиса
//   - TelegramBot::webStop()      — web-обёртка
// ============================================================

#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>


// ============================================================
// STOP
// ============================================================

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


// ============================================================
// WEB API - STOP
// ============================================================

bool TelegramBot::webStop()
{
    if (!serviceExists())
    {
        return false;
    }

    return stopService();
}
