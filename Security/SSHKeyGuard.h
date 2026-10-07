#pragma once

#include <libssh2.h>
#include <string>

class SSHKeyGuard {
public:

    SSHKeyGuard(
        LIBSSH2_SESSION* session,
        const std::string& sudoPassword
    );

    void menu();

    bool webInstall();
    bool webRemove();

    bool webStart();

    bool webStop();

    bool webRestart();

    std::string webStatus();

    bool webBaseline();
    bool webScan();

    std::string webEvents();
    std::string webLogs();

    bool webAudit();
    bool webUpdate();

private:

    LIBSSH2_SESSION* session;
    std::string sudoPassword;

    void installGuard();
    void removeGuard();

    void startGuard();
    void stopGuard();
    void restartGuard();

    void showStatus();

    void initializeBaseline();
    void scanNow();

    void showEvents();
    void showLogs();

    void installAudit();
    void updateGuard();

    bool executeRemote(
        const std::string& command,
        std::string& output,
        int& exitCode
    );

    bool checkRootAccess();

    bool commandExists(
        const std::string& command
    );

    bool serviceExists();
    bool scriptExists();

    bool isServiceActive();
    bool isServiceEnabled();

    bool installPython();
    bool installCurl();
    bool installAuditd();

    bool downloadScript(
        const std::string& url,
        const std::string& destination
    );

    bool validatePythonScript(
        const std::string& path
    );

    bool writeServiceFile();

    bool reloadSystemd();

    bool enableService();

    bool removeServiceFile();

    bool backupCurrentScript();
    bool restoreBackup();

    void printCommandOutput(
        const std::string& output
    );

    void printSeparator();

    std::string shellQuote(
        const std::string& value
    );

    std::string base64Encode(
        const std::string& input
    );
};