#pragma once

#include <string>
#include <libssh2.h>

class TelegramBot
{
private:

    LIBSSH2_SESSION* session;

    std::string sudoPassword;

    bool sudoRequired;
    bool sudoAuthenticated;

    bool executeRemote(
        const std::string& command,
        std::string& output,
        int& exitCode,
        bool useSudo = false
    );

    bool authenticateSudo();

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

    bool enableService();

    bool startService();

    bool stopService();

    bool restartService();

    bool disableService();

    bool serviceExists();

    bool serviceIsActive();

    bool generateVerificationCode();

    bool removeInstallation();

    std::string generateRandomCode();

    std::string readBotToken();

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

    bool updateBot();

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

    bool webInstall();
    bool webInstall(const std::string& token);
    bool webStart();
    bool webStop();
    bool webRestart();
    bool webDisable();
    bool webUpdate();
    bool webGenerateCode();
    bool webRemove();

    std::string webStatus();
    std::string webLogs();

    bool install();
    bool install(const std::string& token);

    bool isActive();

    bool generateCode();
};