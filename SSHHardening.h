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
//   - SSH hardening script management
//   - SSH service status
//   - Configuration backups
//   - Configuration restore
//   - SSH hardening script update
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
        const std::string& password
    );


    // ========================================================
    // MAIN MENU
    // ========================================================

    void menu();


    // ========================================================
    // STATUS
    // ========================================================

    bool isEnabled() const;
};