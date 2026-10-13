
#include "../Security.h"
#include <iostream>
 
bool Security::installSecurity()
{
    std::cout << "\n========================================\n"
        << " ServerGuard Security Installation\n"
        << "========================================\n\n";

    if (!checkRootOrSudo())
    {
        std::cout << "[ERROR] Administrator privileges are required.\n";
        return false;
    }

    std::cout << "Checking server requirements...\n";

    if (!commandExists("systemctl"))
    {
        std::cout << "[ERROR] systemd (systemctl) is required.\n";
        setError("systemd (systemctl) is required.");
        return false;
    }

    std::cout << "[OK] systemctl is available.\n";

    if (!ensureCommand("python3", "python3", "python3"))
        return false;

    if (!checkPythonVersion())
        return false;

    if (!commandExists("curl") && !commandExists("wget"))
    {
        if (!ensureCommand("curl", "curl", "curl"))
            return false;
    }
    else
    {
        std::cout << "[OK] curl/wget is available.\n";
    }

    if (!commandExists("ss"))
        ensureCommand("ss", "iproute2", "iproute");

    if (!commandExists("sshd"))
    {
        std::cout << "[WARN] sshd binary not found in PATH; "
            "SSH port detection may be limited.\n";
    }

    bool firewallManaged = false;

    if (!setupFirewall(firewallManaged))
        return false;

    std::cout << "\nCreating ServerGuard directories...\n";

    if (!createDirectories())
        return false;

    std::cout << "[OK] Directories created.\n";
    std::cout << "\nChecking security script...\n";

    if (!ensureScriptHealthy())
    {
        std::cout << "[ERROR] Could not prepare the security script.\n";
        return false;
    }

    if (!setFilePermissions())
        return false;

    std::cout << "[OK] Security script permissions configured.\n";
    std::cout << "Creating systemd service...\n";

    if (!createSystemdService() || !reloadSystemd())
        return false;

    std::cout << "[OK] Systemd service configured.\n";

    if (!enableService())
    {
        std::cout << "[WARN] Could not enable automatic startup "
            "(the service can still run).\n";
    }
    else
    {
        std::cout << "[OK] Automatic startup enabled.\n";
    }

    registerTrustedClientIp();

    std::cout << "Starting service...\n";

    if (!startService())
    {
        std::cout << "[ERROR] Security service failed to start.\n";
        sshSecurity = false;
        return false;
    }

    std::cout << "[OK] Security service started.\n";
    sshSecurity = true;

    std::cout << "\n========================================\n"
        << " ServerGuard Security ACTIVE\n"
        << "========================================\n\n";

    std::cout << "[OK] Firewall: "
        << (firewallManaged ? "UFW ACTIVE" : "iptables fallback") << "\n";
    std::cout << "[OK] Security script: INSTALLED\n";
    std::cout << "[OK] SSH brute-force protection: ACTIVE\n";
    std::cout << "[OK] systemd automatic startup: ENABLED\n";
    std::cout << "[OK] Security service: RUNNING\n";
    std::cout << "\nProtection is ready.\n";

    return true;
}