#pragma once

#include <string>
#include <libssh2.h>

class SSHHardening
{
private:

    LIBSSH2_SESSION* session;

    std::string sudoPassword;

    bool keyAuthentication;

    bool sudoRequired;

    bool sudoAuthenticated;

    bool hardeningEnabled;

    bool executeRemote(
        const std::string& command,
        std::string& output,
        int& exitCode,
        bool useSudo = false
    );

    bool authenticateSudo();

    bool checkRootOrSudo();

    bool commandExists(
        const std::string& command
    );

    bool checkScript();

    bool setPermissions();

    bool runHardening();

    bool checkHardening();

    bool restoreConfiguration();

    bool showBackups();

    bool checkSSHService();

    bool isSSHConfigValid();

    bool update();

    bool downloadUpdate();

    bool verifyUpdate();

    bool backupCurrentScript();

    bool installUpdatedScript();

    bool rollbackUpdate();

public:

    SSHHardening(
        LIBSSH2_SESSION* sshSession,
        const std::string& password,
        bool isKeyAuthentication
    );

    void menu();

    bool isEnabled() const;

    bool webApply();

    bool webValidate();

    bool webUpdate();

    bool webInstall();

    bool webRemove();

    std::string webStatus();

    std::string webBackups();
};