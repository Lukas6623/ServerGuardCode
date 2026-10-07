#pragma once

// ============================================================
// TelegramBot.h — ПУБЛИЧНЫЙ интерфейс класса.
//
// КАРТА ФАЙЛОВ ПРОЕКТА (где что находится):
// ------------------------------------------------------------
//   TelegramBot.h                              — этот файл, объявление класса
//   TelegramBotInternal.h                      — общие пути и хелперы (shellQuote,
//                                                 base64Encode, trim), подключается
//                                                 всеми .cpp файлами ниже
//
//   TelegramBot.cpp                            — ЯДРО: SSH-исполнение команд,
//                                                 sudo, проверка root, установка
//                                                 python/venv/aiogram, скачивание
//                                                 и установка GitHub-репозитория
//                                                 бота, конфиг, systemd unit-файл,
//                                                 проверки статуса/скрипта,
//                                                 бэкап/восстановление кода,
//                                                 обновление python-библиотек,
//                                                 консольное меню, web-статус/логи
//
//   install/TelegramBot_Install.cpp            — УСТАНОВКА бота
//                                                 (install, webInstall)
//
//   update/TelegramBot_Update.cpp              — ОБНОВЛЕНИЕ бота
//                                                 (updateBot, webUpdate)
//
//   remove/TelegramBot_Remove.cpp              — УДАЛЕНИЕ бота
//                                                 (removeInstallation, webRemove)
//
//   restart/TelegramBot_Restart.cpp            — ПЕРЕЗАПУСК бота
//                                                 (restartService, webRestart)
//
//   generate_code/TelegramBot_GenerateCode.cpp — ГЕНЕРАЦИЯ КОДА верификации
//                                                 (generateRandomCode,
//                                                  generateVerificationCode,
//                                                  generateCode, webGenerateCode)
//
//   stop/TelegramBot_Stop.cpp                  — ОСТАНОВКА бота
//                                                 (stopService, webStop)
//
//   autostart_enable/
//       TelegramBot_EnableAutostart.cpp        — ВКЛЮЧЕНИЕ автозапуска
//                                                 (enableService)
//
//   autostart_disable/
//       TelegramBot_DisableAutostart.cpp       — ОТКЛЮЧЕНИЕ автозапуска
//                                                 (disableService, webDisable)
// ------------------------------------------------------------
// Запуск бота (startService/webStart) отдельной папки не выделен
// (в задаче явно не требовался) и остался в TelegramBot.cpp,
// т.к. используется как внутренний хелпер почти во всех остальных
// операциях (install/update/restart и т.д.).
//
// Все .cpp файлы — это просто определения методов ОДНОГО И ТОГО ЖЕ
// класса TelegramBot в разных файлах (это разрешено в C++, если все
// файлы попадают в один таргет сборки). Ничего в самом классе,
// в его API и в поведении не меняется — меняется только физическое
// расположение кода.
// ============================================================

#include <string>
#include <libssh2.h>

class TelegramBot
{
private:

    LIBSSH2_SESSION* session;

    std::string sudoPassword;

    bool sudoRequired;
    bool sudoAuthenticated;


    // ========================================================
    // SSH  (реализация: TelegramBot.cpp)
    // ========================================================

    bool executeRemote(
        const std::string& command,
        std::string& output,
        int& exitCode,
        bool useSudo = false
    );

    bool authenticateSudo();


    // ========================================================
    // HELPERS
    // ========================================================

    bool commandExists(
        const std::string& command
    );

    bool checkRootOrSudo();

    bool createDirectories();

    bool installPythonDependencies();

    bool downloadBot();

    bool checkScript();

    bool createConfig();
    bool createConfig(
        const std::string& token
    );

    bool installInternal(
        const std::string* webToken
    );
    bool configExists();

    bool createSystemdService();

    bool reloadSystemd();

    bool enableService();      // autostart_enable/TelegramBot_EnableAutostart.cpp

    bool startService();       // TelegramBot.cpp (общий хелпер)

    bool stopService();        // stop/TelegramBot_Stop.cpp

    bool restartService();     // restart/TelegramBot_Restart.cpp

    bool disableService();     // autostart_disable/TelegramBot_DisableAutostart.cpp

    bool serviceExists();

    bool serviceIsActive();

    bool generateVerificationCode();   // generate_code/TelegramBot_GenerateCode.cpp

    bool removeInstallation();         // remove/TelegramBot_Remove.cpp

    std::string generateRandomCode();  // generate_code/TelegramBot_GenerateCode.cpp

    std::string readBotToken();


    // ========================================================
    // GITHUB REPOSITORY  (реализация: TelegramBot.cpp)
    // ========================================================

    bool ensureUnzip();

    bool downloadRepositoryArchive(
        const std::string& archivePath
    );

    bool extractRepository(
        const std::string& archivePath,
        const std::string& extractDirectory,
        std::string& repositoryRoot
    );

    bool validateRepository(
        const std::string& repositoryRoot
    );

    bool installRepositoryFiles(
        const std::string& repositoryRoot
    );

    bool setRepositoryPermissions();


    // ========================================================
    // UPDATE
    // ========================================================

    bool updateBot();   // update/TelegramBot_Update.cpp

    bool downloadUpdateFile(
        const std::string& url,
        const std::string& destination
    );

    bool checkPythonSyntax(
        const std::string& file
    );

    bool updatePythonLibraries();

    bool requirementsExists();

    bool updateRequirements();

    bool backupTelegramCode();

    bool clearTelegramCode();

    bool restoreTelegramCode();

    void showUpdateLogs();


public:

    TelegramBot(
        LIBSSH2_SESSION* sshSession,
        const std::string& password
    );

    void menu();
    // ============================================================
    // WEB API
    // ============================================================

    bool webInstall();          // install/TelegramBot_Install.cpp
    bool webInstall(const std::string& token);
    bool webStart();            // TelegramBot.cpp
    bool webStop();             // stop/TelegramBot_Stop.cpp
    bool webRestart();          // restart/TelegramBot_Restart.cpp
    bool webDisable();          // autostart_disable/TelegramBot_DisableAutostart.cpp
    bool webUpdate();           // update/TelegramBot_Update.cpp
    bool webGenerateCode();     // generate_code/TelegramBot_GenerateCode.cpp
    bool webRemove();           // remove/TelegramBot_Remove.cpp

    std::string webStatus();
    std::string webLogs();
    bool install();              // install/TelegramBot_Install.cpp
    bool install(const std::string& token);

    bool isActive();

    bool generateCode();         // generate_code/TelegramBot_GenerateCode.cpp
};
