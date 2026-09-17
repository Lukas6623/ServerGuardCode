#pragma once

#include <libssh2.h>
#include <string>

class FileGuard
{
public:
    FileGuard(
        LIBSSH2_SESSION* session,
        const std::string& sudoPassword
    );

    void menu();

    bool install();
    bool start();
    bool stop();
    bool disable();
    bool status();
    bool logs();
    bool rebuild();

private:
    LIBSSH2_SESSION* session;
    std::string sudoPassword;

    // ========================================================
    // REMOTE COMMANDS
    // ========================================================

    bool executeRemote(
        const std::string& command,
        std::string* output = nullptr
    );

    bool checkRootOrSudo();

    bool commandExists(
        const std::string& command
    );

    // ========================================================
    // INSTALLATION
    // ========================================================

    bool createDirectories();
    bool setPermissions();

    bool createSystemdService();
    bool reloadSystemd();

    bool enableService();
    bool startService();
    bool stopService();
    bool disableService();

    bool serviceExists();
    bool serviceIsActive();

    // ========================================================
    // UPDATE
    // ========================================================

    bool update();

    bool downloadUpdate();

    bool verifyUpdate();

    bool backupCurrentScript();

    bool installUpdatedScript();

    bool rollbackUpdate();

    // ========================================================
    // INFORMATION
    // ========================================================

    void printStatus();
    void printLogs();

    void rebuildBaseline();
};