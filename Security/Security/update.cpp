
#include "../Security.h"

#include <iostream>
#include <string>


bool Security::updateSecurity()
{
    std::cout << "\n========================================\n       UPDATE SERVERGUARD SECURITY\n========================================\n\n";

    if (!checkRootOrSudo())
    {
        std::cout << "\n[ERROR] Administrator privileges are required.\n";
        return false;
    }

    std::string output;
    int exitCode = -1;

    if (!executeRemote("test -s " + shellQuote(SECURITY_SCRIPT), output, exitCode, true))
    {
        std::cout << "Security is not installed yet. Running the full installation instead...\n";
        return installSecurity();
    }

    if (!ensureCommand("python3", "python3", "python3") || !checkPythonVersion())
    {
        return false;
    }

    if (!commandExists("curl") && !commandExists("wget") && !ensureCommand("curl", "curl", "curl"))
    {
        return false;
    }

    std::cout << "\n[1/7] Downloading new Security script...\n";

    if (!downloadScriptToTemp())
    {
        return false;
    }

    auto cleanupTemp = [&]()
        {
            std::string out;
            int code = -1;
            executeRemote("rm -f " + shellQuote(SECURITY_TEMP_SCRIPT), out, code, true);
        };

    std::cout << "[2/7] Verification passed.\n";

    output.clear();

    if (executeRemote("cmp -s " + shellQuote(SECURITY_TEMP_SCRIPT) + " " + shellQuote(SECURITY_SCRIPT),
        output, exitCode, true))
    {
        cleanupTemp();

        std::cout << "[OK] Already up to date.\n";

        if (!serviceExists())
        {
            createSystemdService();
            reloadSystemd();
            enableService();
        }

        if (!serviceIsActive() && !startService())
        {
            return false;
        }

        registerTrustedClientIp();

        return true;
    }

    std::cout << "[3/7] Creating backup of current Security script...\n";

    if (!backupCurrentSecurityScript())
    {
        cleanupTemp();
        return false;
    }

    std::cout << "[4/7] Installing new Security script...\n";

    if (!installScriptFromTemp())
    {
        cleanupTemp();
        return false;
    }

    std::cout << "[5/7] Verifying installed Security script...\n";

    auto rollbackAndRestart = [&](const std::string& reason) -> bool
        {
            std::cout << "[ERROR] " << reason << "\nStarting rollback...\n";

            rollbackSecurityUpdate();

            std::string out;
            int code = -1;
            executeRemote("systemctl restart " + SECURITY_SERVICE, out, code, true, 60);

            if (waitServiceStable(5))
            {
                std::cout << "[OK] Previous version restored and service is running.\n";
            }
            else
            {
                std::cout << "[ERROR] Previous version restored, but the service is still not running.\n";
                printServiceDiagnostics();
            }

            cleanupTemp();
            setError(reason);

            return false;
        };

    if (!verifyScriptFile(SECURITY_SCRIPT, false))
    {
        return rollbackAndRestart("Installed Security script failed verification.");
    }

    std::cout << "[6/7] Restarting Security service...\n";

    if (!createSystemdService() || !reloadSystemd())
    {
        return rollbackAndRestart("Failed to refresh the systemd service.");
    }

    enableService();

    output.clear();

    if (!executeRemote("systemctl restart " + SECURITY_SERVICE, output, exitCode, true, 60))
    {
        printOutput(output);
        return rollbackAndRestart("Failed to restart the Security service.");
    }

    std::cout << "[7/7] Checking Security service stability...\n";

    if (!waitServiceStable(8))
    {
        return rollbackAndRestart("Security service is not stable after the update.");
    }

    cleanupTemp();
    registerTrustedClientIp();

    sshSecurity = true;

    std::cout << "\n========================================\n SECURITY UPDATE SUCCESSFUL\n========================================\n";

    std::cout << "Source:\n" << SECURITY_UPDATE_URL << "\n\n";
    std::cout << "Script:\n" << SECURITY_SCRIPT << "\n\n";
    std::cout << "Backup:\n" << SECURITY_BACKUP_SCRIPT << "\n\n";
    std::cout << "Service: ACTIVE\n";
    std::cout << "Protection: RUNNING\n";
    std::cout << "Runtime data: PRESERVED\n";
    std::cout << "========================================\n";

    return true;
}
