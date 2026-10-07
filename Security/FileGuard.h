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

    bool executeRemote(
        const std::string& command,
        std::string* output = nullptr
    );

    bool checkRootOrSudo();

    bool commandExists(
        const std::string& command
    );

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

    bool update();

    bool downloadUpdate();

    bool verifyUpdate();

    bool backupCurrentScript();

    bool installUpdatedScript();

    bool rollbackUpdate();

    void printStatus();
    void printLogs();

    void rebuildBaseline();
};