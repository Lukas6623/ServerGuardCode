#pragma once

#include <libssh2.h>
#include <string>


// ============================================================
// SERVERGUARD SECURITY
// ============================================================
//
// Responsible for:
//
//   - SSH brute-force protection
//   - UFW configuration
//   - systemd service management
//   - security module installation
//   - Security script update
//   - Security statistics
//
// ============================================================

class Security
{
public:

    // ========================================================
    // CONSTRUCTOR
    // ========================================================

    Security(
        LIBSSH2_SESSION* sshSession,
        const std::string& password
    );


    // ========================================================
    // MAIN MENU
    // ========================================================

    void menu();


    // ========================================================
    // INSTALL / ENABLE SECURITY
    // ========================================================

    bool installSecurity();


    // ========================================================
    // SECURITY STATE
    // ========================================================

    bool isSSHSecurityEnabled() const;


    // ========================================================
    // WEB DASHBOARD
    // ========================================================

    // Number of blocked threats
    long long webThreats();


    // ========================================================
    // WEB API
    // ========================================================

    bool webInstall();

    bool webStart();

    bool webStop();

    bool webDisable();

    bool webUpdate();

    std::string webStatus();

    std::string webLogs();


private:

    // ========================================================
    // SSH
    // ========================================================

    LIBSSH2_SESSION* session;

    std::string sudoPassword;


    // ========================================================
    // STATE
    // ========================================================

    bool sshSecurity;

    bool sudoRequired;

    bool sudoAuthenticated;


    // ========================================================
    // REMOTE COMMAND EXECUTION
    // ========================================================

    bool executeRemote(
        const std::string& command,
        std::string& output,
        int& exitCode,
        bool useSudo
    );


    // ========================================================
    // COMMAND CHECK
    // ========================================================

    bool commandExists(
        const std::string& command
    );


    // ========================================================
    // SUDO
    // ========================================================

    bool authenticateSudo();

    bool checkRootOrSudo();


    // ========================================================
    // DIRECTORIES
    // ========================================================

    bool createDirectories();


    // ========================================================
    // FILE PERMISSIONS
    // ========================================================

    bool setFilePermissions();


    // ========================================================
    // SYSTEMD
    // ========================================================

    bool createSystemdService();

    bool reloadSystemd();

    bool enableService();

    bool startService();

    bool stopService();

    bool disableService();

    bool serviceExists();

    bool serviceIsActive();


    // ========================================================
    // SECURITY UPDATE
    // ========================================================

    bool updateSecurity();

    bool downloadSecurityUpdate();

    bool verifySecurityUpdate();

    bool backupCurrentSecurityScript();

    bool installUpdatedSecurityScript();

    bool verifyInstalledSecurityScript();

    bool rollbackSecurityUpdate();
};