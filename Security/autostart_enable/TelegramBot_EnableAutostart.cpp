// ============================================================
// autostart_enable/TelegramBot_EnableAutostart.cpp
//
// Категория: ВКЛЮЧЕНИЕ автозапуска бота при старте системы.
//
// Содержит:
//   - TelegramBot::enableService()  — systemctl enable сервиса
//
// Отдельной web-обёртки (webEnable) в исходном коде не было —
// включение автозапуска происходит внутри install()
// (см. install/TelegramBot_Install.cpp).
// ============================================================

#include "../TelegramBot.h"
#include "../TelegramBotInternal.h"

#include <iostream>


// ============================================================
// ENABLE
// ============================================================

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
