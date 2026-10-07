
#pragma once

#include <string>
#include <libssh2.h>


// ============================================================
// SERVERGUARD SSH HARDENING
// ============================================================
//
// Responsible for:
//
//   - SSH configuration hardening
//   - SSH configuration validation
//   - SSH service status
//   - Configuration backups
//   - Configuration restore
//   - SSH hardening script management
//   - SSH hardening script update
//   - Web API integration
//
// ============================================================

class SSHHardening
{
private:

    // ========================================================
    // SSH CONNECTION
    // ========================================================

    LIBSSH2_SESSION* session;

    std::string sudoPassword;

    // Current SSH authentication method.
    //
    // true  = authenticated using SSH private key
    // false = authenticated using password
    //
    // Password authentication must NOT be disabled when
    // ServerGuard itself is connected using password.
    bool keyAuthentication;


    // ========================================================
    // SUDO STATE
    // ========================================================

    bool sudoRequired;

    bool sudoAuthenticated;


    // ========================================================
    // HARDENING STATE
    // ========================================================

    bool hardeningEnabled;


    // ========================================================
    // REMOTE COMMAND EXECUTION
    // ========================================================

    bool executeRemote(
        const std::string& command,
        std::string& output,
        int& exitCode,
        bool useSudo = false
    );


    // ========================================================
    // SUDO
    // ========================================================

    bool authenticateSudo();

    bool checkRootOrSudo();


    // ========================================================
    // SYSTEM
    // ========================================================

    bool commandExists(
        const std::string& command
    );


    // ========================================================
    // HARDENING SCRIPT
    // ========================================================

    bool checkScript();

    bool setPermissions();


    // ========================================================
    // APPLY HARDENING
    // ========================================================

    bool runHardening();

    bool checkHardening();


    // ========================================================
    // CONFIGURATION BACKUPS
    // ========================================================

    bool restoreConfiguration();

    bool showBackups();


    // ========================================================
    // SSH SERVICE
    // ========================================================

    bool checkSSHService();


    // ========================================================
    // SSH CONFIGURATION VALIDATION
    // ========================================================

    bool isSSHConfigValid();


    // ========================================================
    // UPDATE SSH HARDENING SCRIPT
    // ========================================================

    bool update();

    bool downloadUpdate();

    bool verifyUpdate();

    bool backupCurrentScript();

    bool installUpdatedScript();

    bool rollbackUpdate();


public:

    // ========================================================
    // CONSTRUCTOR
    // ========================================================

    SSHHardening(
        LIBSSH2_SESSION* sshSession,
        const std::string& password,
        bool isKeyAuthentication
    );


    // ========================================================
    // CONSOLE MENU
    // ========================================================

    void menu();


    // ========================================================
    // BASIC STATUS
    // ========================================================

    bool isEnabled() const;


    // ========================================================
    // WEB API
    // ========================================================

    bool webApply();

    bool webValidate();

    bool webUpdate();
    bool webInstall();
    bool webRemove();
    std::string webStatus();

    std::string webBackups();
};
