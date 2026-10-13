#pragma once

#include <libssh2.h>

#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

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

    bool webUninstall();

    std::string webStatus();

    std::string webLogs();

    // ---- Runtime recovery API (no program restart needed) ----

    // Replace the SSH session (e.g. after the connection was re-established).
    void setSession(LIBSSH2_SESSION* sshSession);

    // Change the sudo password at runtime; resets the failed-auth counter.
    void setSudoPassword(const std::string& password);

    // Optional: called automatically when the SSH connection drops.
    // Must return a NEW, authenticated session (or nullptr on failure).
    void setReconnectCallback(std::function<LIBSSH2_SESSION* ()> callback);

    // Human readable description of the last error.
    std::string getLastError() const;

private:

    LIBSSH2_SESSION* session;

    std::string sudoPassword;

    bool sshSecurity;

    bool sudoRequired;

    bool sudoAuthenticated;

    bool sudoNoPassword;

    bool needPty;

    bool inPrivilegeCheck;

    int privilegeFailures;

    std::time_t lastPrivilegeAttempt;

    std::string lastError;

    std::function<LIBSSH2_SESSION* ()> reconnectCallback;

    std::shared_ptr<std::recursive_mutex> mutex_;

    // ---- SSH transport ----
    bool executeRemote(
        const std::string& command,
        std::string& output,
        int& exitCode,
        bool useSudo,
        int timeoutSec = 60
    );

    int executeOnce(
        const std::string& command,
        std::string& output,
        int& exitCode,
        bool elevated,
        int timeoutSec
    );

    bool reconnect();
    void setError(const std::string& message);

    // ---- Privileges ----
    bool ensurePrivileges();
    bool checkPrivileges(bool verbose);
    bool authenticateSudo();
    bool checkRootOrSudo();

    // ---- Environment / packages ----
    bool commandExists(const std::string& command);
    bool ensureCommand(const std::string& command, const std::string& aptPackage, const std::string& rpmPackage);
    std::string detectPackageManager();
    bool installPackages(const std::vector<std::string>& packages);
    bool checkPythonVersion();
    std::string pythonPath();

    // ---- Firewall ----
    std::vector<std::string> detectSshPorts();
    std::vector<std::string> listeningPorts(bool udp);
    bool ufwIsActive();
    bool setupFirewall(bool& firewallManaged);

    // ---- Files / service ----
    bool createDirectories();
    bool setFilePermissions();
    bool createSystemdService();
    bool reloadSystemd();
    bool enableService();
    bool startService();
    bool startServiceOnce();
    bool stopService();
    bool disableService();
    bool serviceExists();
    bool serviceIsActive();
    int serviceRestartCount();
    bool waitServiceStable(int seconds);
    bool repairService();
    void printServiceDiagnostics();

    // ---- Script management ----
    bool ensureScriptHealthy();
    bool downloadScriptToTemp();
    bool verifyScriptFile(const std::string& path, bool runSelfTest);
    bool backupCurrentSecurityScript();
    bool installScriptFromTemp();
    bool rollbackSecurityUpdate();
    void registerTrustedClientIp();

    // ---- High level operations ----
    bool updateSecurity();
    bool uninstallSecurity();
};