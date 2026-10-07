#pragma once

#include <libssh2.h>
#include <string>

class Security
{
public:

    Security(
        LIBSSH2_SESSION* sshSession,
        const std::string& password
    );

    void menu();

    bool installSecurity();

    bool isSSHSecurityEnabled() const;

    long long webThreats();

    bool webInstall();

    bool webStart();

    bool webStop();

    bool webDisable();

    bool webUpdate();

    std::string webStatus();

    std::string webLogs();

private:

    LIBSSH2_SESSION* session;

    std::string sudoPassword;

    bool sshSecurity;

    bool sudoRequired;

    bool sudoAuthenticated;

    bool executeRemote(
        const std::string& command,
        std::string& output,
        int& exitCode,
        bool useSudo
    );

    bool commandExists(
        const std::string& command
    );

    bool authenticateSudo();

    bool checkRootOrSudo();

    bool createDirectories();

    bool setFilePermissions();

    bool createSystemdService();

    bool reloadSystemd();

    bool enableService();

    bool startService();

    bool stopService();

    bool disableService();

    bool serviceExists();

    bool serviceIsActive();

    bool updateSecurity();

    bool downloadSecurityUpdate();

    bool verifySecurityUpdate();

    bool backupCurrentSecurityScript();

    bool installUpdatedSecurityScript();

    bool verifyInstalledSecurityScript();

    bool rollbackSecurityUpdate();
};