#include "Security.h"

#include <libssh2.h>

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cctype>


// ============================================================
// CONFIGURATION
// ============================================================

static const std::string SECURITY_DIR =
"/opt/serverguard";

static const std::string SECURITY_DATA_DIR =
"/opt/serverguard/data";

static const std::string SECURITY_SCRIPT =
"/opt/serverguard/brute_force_guard.py";

static const std::string SECURITY_TEMP_SCRIPT =
"/opt/serverguard/brute_force_guard.py.update";

static const std::string SECURITY_SERVICE =
"serverguard-security.service";

static const std::string SECURITY_SERVICE_PATH =
"/etc/systemd/system/serverguard-security.service";


// ============================================================
// SECURITY UPDATE CONFIGURATION
// ============================================================

static const std::string SECURITY_UPDATE_URL =
"https://raw.githubusercontent.com/"
"Lukas6623/ServerGuard/main/brute_force_guard.py";

static const std::string SECURITY_BACKUP_DIR =
"/opt/serverguard/backups/security";

static const std::string SECURITY_BACKUP_SCRIPT =
"/opt/serverguard/backups/security/brute_force_guard.py";


// ============================================================
// BASE64 ENCODE
// ============================================================

static std::string base64Encode(
    const std::string& input)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string result;

    int value = 0;
    int bits = -6;

    for (unsigned char c : input)
    {
        value = (value << 8) + c;
        bits += 8;

        while (bits >= 0)
        {
            result.push_back(
                table[(value >> bits) & 0x3F]
            );

            bits -= 6;
        }
    }

    if (bits > -6)
    {
        result.push_back(
            table[
                ((value << 8) >>
                    (bits + 8)) & 0x3F
            ]
        );
    }

    while (result.size() % 4)
    {
        result.push_back('=');
    }

    return result;
}


// ============================================================
// SHELL QUOTE
// ============================================================

static std::string shellQuote(
    const std::string& value)
{
    std::string result = "'";

    for (char c : value)
    {
        if (c == '\'')
        {
            result += "'\\''";
        }
        else
        {
            result += c;
        }
    }

    result += "'";

    return result;
}


// ============================================================
// TRIM
// ============================================================

static std::string trim(
    const std::string& value)
{
    size_t start = 0;

    while (start < value.size())
    {
        unsigned char c =
            static_cast<unsigned char>(
                value[start]);

        if (!std::isspace(c))
        {
            break;
        }

        ++start;
    }

    size_t end = value.size();

    while (end > start)
    {
        unsigned char c =
            static_cast<unsigned char>(
                value[end - 1]);

        if (!std::isspace(c))
        {
            break;
        }

        --end;
    }

    return value.substr(
        start,
        end - start
    );
}


// ============================================================
// CONSTRUCTOR
// ============================================================

Security::Security(
    LIBSSH2_SESSION* sshSession,
    const std::string& password)
    :
    session(sshSession),
    sudoPassword(password),
    sshSecurity(false),
    sudoRequired(false),
    sudoAuthenticated(false)
{}


// ============================================================
// EXECUTE REMOTE COMMAND
// ============================================================

bool Security::executeRemote(
    const std::string& command,
    std::string& output,
    int& exitCode,
    bool useSudo)
{
    output.clear();
    exitCode = -1;

    if (session == nullptr)
    {
        output =
            "SSH session is not available.";

        return false;
    }

    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(session);

    if (channel == nullptr)
    {
        output =
            "Failed to open SSH channel.";

        return false;
    }

    libssh2_channel_setenv(
        channel,
        "LC_ALL",
        "C"
    );

    std::string finalCommand;

    if (useSudo)
    {
        if (sudoPassword.empty())
        {
            output =
                "Sudo password is empty.";

            libssh2_channel_free(channel);

            return false;
        }

        finalCommand =
            "sudo -S -p '' bash -c " +
            shellQuote(command);
    }
    else
    {
        finalCommand = command;
    }

    if (libssh2_channel_exec(
        channel,
        finalCommand.c_str()) != 0)
    {
        output =
            "Failed to execute remote command.";

        libssh2_channel_close(channel);
        libssh2_channel_free(channel);

        return false;
    }

    libssh2_channel_handle_extended_data2(
        channel,
        LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
    );

    if (useSudo)
    {
        std::string passwordLine =
            sudoPassword + "\n";

        libssh2_channel_write(
            channel,
            passwordLine.c_str(),
            passwordLine.size()
        );
    }

    char buffer[4096];

    while (true)
    {
        ssize_t bytesRead =
            libssh2_channel_read(
                channel,
                buffer,
                sizeof(buffer)
            );

        if (bytesRead > 0)
        {
            output.append(
                buffer,
                static_cast<size_t>(
                    bytesRead)
            );

            continue;
        }

        if (bytesRead == 0)
        {
            if (libssh2_channel_eof(channel))
            {
                break;
            }

            continue;
        }

        break;
    }

    libssh2_channel_send_eof(channel);
    libssh2_channel_wait_eof(channel);
    libssh2_channel_wait_closed(channel);

    exitCode =
        libssh2_channel_get_exit_status(
            channel);

    libssh2_channel_free(channel);

    return exitCode == 0;
}


// ============================================================
// CHECK COMMAND
// ============================================================

bool Security::commandExists(
    const std::string& command)
{
    std::string output;
    int exitCode = -1;

    return executeRemote(
        "command -v " +
        shellQuote(command) +
        " >/dev/null 2>&1",
        output,
        exitCode,
        false
    );
}


// ============================================================
// SUDO AUTHENTICATION
// ============================================================

bool Security::authenticateSudo()
{
    if (session == nullptr)
    {
        return false;
    }

    if (sudoPassword.empty())
    {
        return false;
    }

    std::string output;
    int exitCode = -1;

    bool result =
        executeRemote(
            "true",
            output,
            exitCode,
            true
        );

    if (result && exitCode == 0)
    {
        sudoAuthenticated = true;

        return true;
    }

    sudoAuthenticated = false;

    return false;
}


// ============================================================
// CHECK ROOT OR SUDO
// ============================================================

bool Security::checkRootOrSudo()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "id -u",
        output,
        exitCode,
        false))
    {
        std::cout
            << "[ERROR] Cannot determine current user.\n";

        return false;
    }

    output = trim(output);

    if (output == "0")
    {
        sudoRequired = false;
        sudoAuthenticated = true;

        return true;
    }

    sudoRequired = true;

    if (sudoPassword.empty())
    {
        std::cout
            << "[ERROR] Sudo password is empty.\n";

        return false;
    }

    std::cout
        << "Administrator privileges are required.\n";

    if (!authenticateSudo())
    {
        std::cout
            << "[ERROR] Sudo authentication failed.\n";

        return false;
    }

    return true;
}


// ============================================================
// CREATE DIRECTORIES
// ============================================================

bool Security::createDirectories()
{
    std::string output;
    int exitCode = -1;

    std::string command =
        "mkdir -p " +
        shellQuote(SECURITY_DIR) +
        " " +
        shellQuote(SECURITY_DATA_DIR);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to create "
            "ServerGuard directories.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    if (!executeRemote(
        "chmod 700 " +
        shellQuote(SECURITY_DATA_DIR),
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to set "
            "data directory permissions.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    return true;
}


// ============================================================
// SET SCRIPT PERMISSIONS
// ============================================================

bool Security::setFilePermissions()
{
    std::string output;
    int exitCode = -1;

    std::string command =
        "chown root:root " +
        shellQuote(SECURITY_SCRIPT) +
        " && chmod 700 " +
        shellQuote(SECURITY_SCRIPT);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to set "
            "security script permissions.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    return true;
}


// ============================================================
// CREATE SYSTEMD SERVICE
// ============================================================

bool Security::createSystemdService()
{
    const std::string serviceContent =
        "[Unit]\n"
        "Description=ServerGuard SSH Brute Force Protection\n"
        "After=network-online.target ssh.service sshd.service\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "\n"
        "ExecStart=/usr/bin/python3 "
        "/opt/serverguard/brute_force_guard.py\n"
        "\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "\n"
        "User=root\n"
        "Group=root\n"
        "\n"
        "WorkingDirectory=/opt/serverguard\n"
        "\n"
        "NoNewPrivileges=false\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    std::string encoded =
        base64Encode(serviceContent);

    std::string output;
    int exitCode = -1;

    std::string command =
        "echo " +
        shellQuote(encoded) +
        " | base64 -d > " +
        shellQuote(SECURITY_SERVICE_PATH) +
        " && chmod 644 " +
        shellQuote(SECURITY_SERVICE_PATH) +
        " && chown root:root " +
        shellQuote(SECURITY_SERVICE_PATH);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to create "
            "systemd service.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    return true;
}


// ============================================================
// RELOAD SYSTEMD
// ============================================================

bool Security::reloadSystemd()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "systemctl daemon-reload",
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] systemd daemon-reload failed.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    return true;
}


// ============================================================
// ENABLE SERVICE
// ============================================================

bool Security::enableService()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "systemctl enable " +
        SECURITY_SERVICE,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to enable "
            "security service.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    return true;
}


// ============================================================
// START SERVICE
// ============================================================

bool Security::startService()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "systemctl restart " +
        SECURITY_SERVICE,
        output,
        exitCode,
        true))
    {
        sshSecurity = false;

        std::cout
            << "[ERROR] Failed to start "
            "security service.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    if (!serviceIsActive())
    {
        sshSecurity = false;

        return false;
    }

    sshSecurity = true;

    return true;
}


// ============================================================
// STOP SERVICE
// ============================================================

bool Security::stopService()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "systemctl stop " +
        SECURITY_SERVICE,
        output,
        exitCode,
        true))
    {
        return false;
    }

    sshSecurity = false;

    return true;
}


// ============================================================
// DISABLE SERVICE
// ============================================================

bool Security::disableService()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "systemctl disable " +
        SECURITY_SERVICE,
        output,
        exitCode,
        true))
    {
        return false;
    }

    sshSecurity = false;

    return true;
}


// ============================================================
// SERVICE EXISTS
// ============================================================

bool Security::serviceExists()
{
    std::string output;
    int exitCode = -1;

    return executeRemote(
        "test -f " +
        shellQuote(SECURITY_SERVICE_PATH),
        output,
        exitCode,
        false
    );
}


// ============================================================
// SERVICE ACTIVE
// ============================================================

bool Security::serviceIsActive()
{
    std::string output;
    int exitCode = -1;

    bool active =
        executeRemote(
            "systemctl is-active --quiet " +
            SECURITY_SERVICE,
            output,
            exitCode,
            false
        );

    sshSecurity = active;

    return active;
}


// ============================================================
// FIREWALL SETUP
// ============================================================

static bool setupSecurityFirewall(
    Security* security)
{
    if (security == nullptr)
    {
        return false;
    }

    std::cout
        << "\n"
        << "----------------------------------------\n"
        << " Firewall configuration\n"
        << "----------------------------------------\n";

    return true;
}


// ============================================================
// INSTALL SECURITY
// ============================================================

bool Security::installSecurity()
{
    std::cout
        << "\n"
        << "========================================\n"
        << " ServerGuard Security Installation\n"
        << "========================================\n\n";


    // ========================================================
    // 1. ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        std::cout
            << "\n[ERROR] Administrator privileges "
            "are required.\n";

        return false;
    }


    // ========================================================
    // 2. REQUIRED COMMANDS
    // ========================================================

    std::cout
        << "Checking server requirements...\n";

    if (!commandExists("python3"))
    {
        std::cout
            << "[ERROR] python3 is not installed.\n";

        return false;
    }

    if (!commandExists("systemctl"))
    {
        std::cout
            << "[ERROR] systemctl is not available.\n";

        return false;
    }

    if (!commandExists("base64"))
    {
        std::cout
            << "[ERROR] base64 is not available.\n";

        return false;
    }

    if (!commandExists("apt-get"))
    {
        std::cout
            << "[ERROR] apt-get is not available.\n";

        return false;
    }


    // ========================================================
    // 3. UFW
    // ========================================================

    if (!commandExists("ufw"))
    {
        std::cout
            << "\nUFW is not installed.\n"
            << "Installing UFW...\n";

        std::string output;
        int exitCode = -1;

        std::string command =
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y ufw";

        if (!executeRemote(
            command,
            output,
            exitCode,
            true))
        {
            std::cout
                << "[ERROR] Failed to install UFW.\n";

            if (!output.empty())
            {
                std::cout << output << "\n";
            }

            return false;
        }

        if (!commandExists("ufw"))
        {
            std::cout
                << "[ERROR] UFW installation failed.\n";

            return false;
        }

        std::cout
            << "[OK] UFW installed.\n";
    }
    else
    {
        std::cout
            << "[OK] UFW is already installed.\n";
    }


    // ========================================================
    // 4. SSHD
    // ========================================================

    if (!commandExists("sshd"))
    {
        std::cout
            << "[ERROR] sshd is not available.\n";

        return false;
    }


    // ========================================================
    // 5. DETECT SSH PORTS
    // ========================================================

    std::cout
        << "Detecting SSH ports...\n";

    std::string output;
    int exitCode = -1;

    bool sshConfigOk =
        executeRemote(
            "sshd -T 2>/dev/null | "
            "awk '$1 == \"port\" {print $2}'",
            output,
            exitCode,
            false
        );

    std::vector<std::string> sshPorts;

    if (sshConfigOk)
    {
        std::istringstream stream(output);

        std::string port;

        while (stream >> port)
        {
            if (port.empty())
            {
                continue;
            }

            bool numeric = true;

            for (char c : port)
            {
                if (!std::isdigit(
                    static_cast<unsigned char>(c)))
                {
                    numeric = false;
                    break;
                }
            }

            if (!numeric)
            {
                continue;
            }

            try
            {
                int portNumber =
                    std::stoi(port);

                if (portNumber < 1 ||
                    portNumber > 65535)
                {
                    continue;
                }
            }
            catch (...)
            {
                continue;
            }

            bool alreadyAdded = false;

            for (const std::string& existingPort :
                sshPorts)
            {
                if (existingPort == port)
                {
                    alreadyAdded = true;
                    break;
                }
            }

            if (!alreadyAdded)
            {
                sshPorts.push_back(port);
            }
        }
    }


    // ========================================================
    // 6. FALLBACK PORT 22
    // ========================================================

    if (sshPorts.empty())
    {
        std::cout
            << "Could not determine SSH port "
            "from sshd -T.\n";

        std::cout
            << "Checking port 22...\n";

        output.clear();
        exitCode = -1;

        bool port22Listening =
            executeRemote(
                "ss -ltn 2>/dev/null | "
                "awk '$4 ~ /(^|:)22$/ "
                "{found=1} "
                "END {exit(found ? 0 : 1)}'",
                output,
                exitCode,
                false
            );

        if (port22Listening)
        {
            sshPorts.push_back("22");

            std::cout
                << "[OK] SSH port 22 detected.\n";
        }
        else
        {
            std::cout
                << "[ERROR] Could not determine "
                "SSH port safely.\n";

            std::cout
                << "UFW will not be enabled.\n";

            return false;
        }
    }


    // ========================================================
    // 7. ALLOW SSH PORTS
    // ========================================================

    std::cout
        << "Detected SSH port(s): ";

    for (size_t i = 0;
        i < sshPorts.size();
        ++i)
    {
        std::cout
            << sshPorts[i];

        if (i + 1 < sshPorts.size())
        {
            std::cout
                << ", ";
        }
    }

    std::cout
        << "\n";

    for (const std::string& port :
        sshPorts)
    {
        std::cout
            << "Allowing SSH port "
            << port
            << "/tcp...\n";

        output.clear();
        exitCode = -1;

        std::string command =
            "ufw allow " +
            shellQuote(port + "/tcp");

        if (!executeRemote(
            command,
            output,
            exitCode,
            true))
        {
            std::cout
                << "[ERROR] Failed to allow SSH port "
                << port
                << ".\n";

            if (!output.empty())
            {
                std::cout << output << "\n";
            }

            return false;
        }
    }


    // ========================================================
    // 8. ENABLE UFW
    // ========================================================

    std::cout
        << "Enabling UFW...\n";

    output.clear();
    exitCode = -1;

    if (!executeRemote(
        "ufw --force enable",
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to enable UFW.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    // ========================================================
    // 9. VERIFY UFW
    // ========================================================

    output.clear();
    exitCode = -1;

    if (!executeRemote(
        "ufw status verbose",
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to read UFW status.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    std::cout
        << "\nFirewall status:\n"
        << output
        << "\n";

    std::string firewallCheck;
    int firewallExitCode = -1;

    if (!executeRemote(
        "ufw status | "
        "grep -q '^Status: active'",
        firewallCheck,
        firewallExitCode,
        false))
    {
        std::cout
            << "[ERROR] UFW is not active.\n";

        return false;
    }

    std::cout
        << "[OK] UFW is active.\n";


    // ========================================================
    // 10. SERVERGUARD DIRECTORIES
    // ========================================================

    std::cout
        << "\nCreating ServerGuard directories...\n";

    if (!createDirectories())
    {
        return false;
    }

    std::cout
        << "[OK] Directories created.\n";


    // ========================================================
    // 11. SECURITY SCRIPT
    // ========================================================

    std::cout
        << "\nChecking security script...\n";

    output.clear();
    exitCode = -1;

    if (!executeRemote(
        "test -s " +
        shellQuote(SECURITY_SCRIPT),
        output,
        exitCode,
        false))
    {
        std::cout
            << "[ERROR] Security script is missing:\n"
            << SECURITY_SCRIPT
            << "\n";

        std::cout
            << "Install brute_force_guard.py first.\n";

        return false;
    }

    std::cout
        << "[OK] Security script found.\n";


    // ========================================================
    // 12. PYTHON SYNTAX CHECK
    // ========================================================

    output.clear();
    exitCode = -1;

    if (!executeRemote(
        "python3 -m py_compile " +
        shellQuote(SECURITY_SCRIPT),
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Python syntax check failed.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    std::cout
        << "[OK] Python syntax check passed.\n";


    // ========================================================
    // 13. SCRIPT PERMISSIONS
    // ========================================================

    if (!setFilePermissions())
    {
        return false;
    }

    std::cout
        << "[OK] Security script permissions configured.\n";


    // ========================================================
    // 14. SYSTEMD SERVICE
    // ========================================================

    if (!serviceExists())
    {
        std::cout
            << "Creating systemd service...\n";

        if (!createSystemdService())
        {
            return false;
        }

        std::cout
            << "[OK] Systemd service created.\n";
    }
    else
    {
        std::cout
            << "[OK] Systemd service already exists.\n";
    }


    // ========================================================
    // 15. SYSTEMD RELOAD
    // ========================================================

    if (!reloadSystemd())
    {
        return false;
    }

    std::cout
        << "[OK] systemd reloaded.\n";


    // ========================================================
    // 16. ENABLE
    // ========================================================

    if (!enableService())
    {
        return false;
    }

    std::cout
        << "[OK] Automatic startup enabled.\n";


    // ========================================================
    // 17. START
    // ========================================================

    if (!startService())
    {
        std::cout
            << "[ERROR] Security service failed to start.\n";

        std::string statusOutput;
        int statusExitCode = -1;

        executeRemote(
            "systemctl status " +
            SECURITY_SERVICE +
            " --no-pager -l",
            statusOutput,
            statusExitCode,
            true
        );

        if (!statusOutput.empty())
        {
            std::cout
                << "\n"
                << statusOutput
                << "\n";
        }

        return false;
    }

    std::cout
        << "[OK] Security service started.\n";


    // ========================================================
    // 18. FINAL CHECK
    // ========================================================

    if (!serviceIsActive())
    {
        std::cout
            << "[ERROR] Security service is not active.\n";

        std::string statusOutput;
        int statusExitCode = -1;

        executeRemote(
            "systemctl status " +
            SECURITY_SERVICE +
            " --no-pager -l",
            statusOutput,
            statusExitCode,
            true
        );

        if (!statusOutput.empty())
        {
            std::cout
                << "\n"
                << statusOutput
                << "\n";
        }

        sshSecurity = false;

        return false;
    }


    // ========================================================
    // SUCCESS
    // ========================================================

    sshSecurity = true;

    std::cout
        << "\n"
        << "========================================\n"
        << " ServerGuard Security ACTIVE\n"
        << "========================================\n\n";

    std::cout
        << "[OK] UFW firewall: ACTIVE\n";

    std::cout
        << "[OK] SSH brute-force protection: ACTIVE\n";

    std::cout
        << "[OK] systemd automatic startup: ENABLED\n";

    std::cout
        << "[OK] Security service: RUNNING\n";

    std::cout
        << "\nProtection is ready.\n";

    return true;
}


// ============================================================
// SECURITY STATE
// ============================================================

bool Security::isSSHSecurityEnabled() const
{
    return sshSecurity;
}


// ============================================================
// DOWNLOAD SECURITY UPDATE
// ============================================================

bool Security::downloadSecurityUpdate()
{
    std::cout
        << "\n"
        << "[1/7] Downloading new Security script...\n";

    std::string output;
    int exitCode = -1;

    // Remove old temporary file first.

    executeRemote(
        "rm -f " +
        shellQuote(SECURITY_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );

    output.clear();
    exitCode = -1;

    std::string command =
        "curl -fL "
        "--connect-timeout 15 "
        "--max-time 120 "
        "--retry 2 "
        "-o " +
        shellQuote(SECURITY_TEMP_SCRIPT) +
        " " +
        shellQuote(SECURITY_UPDATE_URL);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to download "
            "Security script.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    output.clear();
    exitCode = -1;

    if (!executeRemote(
        "test -s " +
        shellQuote(SECURITY_TEMP_SCRIPT),
        output,
        exitCode,
        false))
    {
        std::cout
            << "[ERROR] Downloaded file is empty.\n";

        return false;
    }

    std::cout
        << "Download completed.\n";

    return true;
}


// ============================================================
// VERIFY SECURITY UPDATE
// ============================================================

bool Security::verifySecurityUpdate()
{
    std::cout
        << "[2/7] Checking Python syntax...\n";

    std::string output;
    int exitCode = -1;

    std::string command =
        "python3 -c " +
        shellQuote(
            "import ast,sys;"
            "p=open(sys.argv[1],encoding='utf-8').read();"
            "ast.parse(p,filename=sys.argv[1]);"
            "print('Python syntax: OK')"
        ) +
        " " +
        shellQuote(SECURITY_TEMP_SCRIPT);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Python syntax verification failed.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    if (!output.empty())
    {
        std::cout
            << output;
    }

    std::cout
        << "Security update verification completed.\n";

    return true;
}


// ============================================================
// BACKUP CURRENT SECURITY SCRIPT
// ============================================================

bool Security::backupCurrentSecurityScript()
{
    std::cout
        << "[3/7] Creating backup of current Security script...\n";

    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "test -s " +
        shellQuote(SECURITY_SCRIPT),
        output,
        exitCode,
        false))
    {
        std::cout
            << "[ERROR] Current Security script "
            "does not exist.\n";

        return false;
    }

    if (!executeRemote(
        "mkdir -p " +
        shellQuote(SECURITY_BACKUP_DIR),
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to create backup directory.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    std::string command =
        "cp -f " +
        shellQuote(SECURITY_SCRIPT) +
        " " +
        shellQuote(SECURITY_BACKUP_SCRIPT) +
        " && "
        "chown root:root " +
        shellQuote(SECURITY_BACKUP_SCRIPT) +
        " && "
        "chmod 700 " +
        shellQuote(SECURITY_BACKUP_SCRIPT);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to create Security backup.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    std::cout
        << "Backup created:\n"
        << SECURITY_BACKUP_SCRIPT
        << "\n";

    return true;
}


// ============================================================
// INSTALL UPDATED SECURITY SCRIPT
// ============================================================

bool Security::installUpdatedSecurityScript()
{
    std::cout
        << "[4/7] Installing new Security script...\n";

    std::string output;
    int exitCode = -1;

    std::string command =
        "mv -f " +
        shellQuote(SECURITY_TEMP_SCRIPT) +
        " " +
        shellQuote(SECURITY_SCRIPT) +
        " && "
        "chown root:root " +
        shellQuote(SECURITY_SCRIPT) +
        " && "
        "chmod 700 " +
        shellQuote(SECURITY_SCRIPT);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to install "
            "new Security script.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    return true;
}


// ============================================================
// VERIFY INSTALLED SECURITY SCRIPT
// ============================================================

bool Security::verifyInstalledSecurityScript()
{
    std::cout
        << "[5/7] Verifying installed Security script...\n";

    std::string output;
    int exitCode = -1;

    std::string command =
        "python3 -c " +
        shellQuote(
            "import ast,sys;"
            "p=open(sys.argv[1],encoding='utf-8').read();"
            "ast.parse(p,filename=sys.argv[1]);"
            "print('Installed Security script: OK')"
        ) +
        " " +
        shellQuote(SECURITY_SCRIPT);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Installed Security script "
            "verification failed.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    if (!output.empty())
    {
        std::cout
            << output;
    }

    return true;
}


// ============================================================
// ROLLBACK SECURITY UPDATE
// ============================================================

bool Security::rollbackSecurityUpdate()
{
    std::cout
        << "\n"
        << "[ROLLBACK] Restoring previous Security script...\n";

    std::string output;
    int exitCode = -1;

    std::string command =
        "test -s " +
        shellQuote(SECURITY_BACKUP_SCRIPT) +
        " && "
        "cp -f " +
        shellQuote(SECURITY_BACKUP_SCRIPT) +
        " " +
        shellQuote(SECURITY_SCRIPT) +
        " && "
        "chown root:root " +
        shellQuote(SECURITY_SCRIPT) +
        " && "
        "chmod 700 " +
        shellQuote(SECURITY_SCRIPT);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Rollback failed.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    std::cout
        << "[OK] Previous Security script restored.\n";

    return true;
}


// ============================================================
// UPDATE SECURITY
// ============================================================

bool Security::updateSecurity()
{
    std::cout
        << "\n"
        << "========================================\n"
        << "       UPDATE SERVERGUARD SECURITY\n"
        << "========================================\n\n";

    if (!checkRootOrSudo())
    {
        std::cout
            << "\n[ERROR] Administrator privileges "
            "are required.\n";

        return false;
    }

    std::string userOutput;
    int userExitCode = -1;

    if (executeRemote(
        "whoami",
        userOutput,
        userExitCode,
        false))
    {
        std::cout
            << "Remote user is "
            << trim(userOutput)
            << ".\n";
    }

    // ========================================================
    // CHECK CURRENT SCRIPT
    // ========================================================

    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "test -s " +
        shellQuote(SECURITY_SCRIPT),
        output,
        exitCode,
        false))
    {
        std::cout
            << "\n[ERROR] Current Security script "
            "does not exist:\n"
            << SECURITY_SCRIPT
            << "\n";

        return false;
    }


    // ========================================================
    // CHECK PYTHON
    // ========================================================

    if (!commandExists("python3"))
    {
        std::cout
            << "[ERROR] python3 is not installed.\n";

        return false;
    }


    // ========================================================
    // CHECK CURL
    // ========================================================

    if (!commandExists("curl"))
    {
        std::cout
            << "\n"
            << "curl is not installed.\n"
            << "Installing curl...\n";

        output.clear();
        exitCode = -1;

        std::string command =
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y curl";

        if (!executeRemote(
            command,
            output,
            exitCode,
            true))
        {
            std::cout
                << "[ERROR] Failed to install curl.\n";

            if (!output.empty())
            {
                std::cout
                    << output
                    << "\n";
            }

            return false;
        }

        if (!commandExists("curl"))
        {
            std::cout
                << "[ERROR] curl installation failed.\n";

            return false;
        }

        std::cout
            << "[OK] curl installed.\n";
    }


    // ========================================================
    // DOWNLOAD
    // ========================================================

    if (!downloadSecurityUpdate())
    {
        return false;
    }


    // ========================================================
    // VERIFY
    // ========================================================

    if (!verifySecurityUpdate())
    {
        executeRemote(
            "rm -f " +
            shellQuote(SECURITY_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );

        return false;
    }


    // ========================================================
    // BACKUP
    // ========================================================

    if (!backupCurrentSecurityScript())
    {
        executeRemote(
            "rm -f " +
            shellQuote(SECURITY_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );

        return false;
    }


    // ========================================================
    // INSTALL
    // ========================================================

    if (!installUpdatedSecurityScript())
    {
        executeRemote(
            "rm -f " +
            shellQuote(SECURITY_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );

        return false;
    }


    // ========================================================
    // VERIFY INSTALLED FILE
    // ========================================================

    if (!verifyInstalledSecurityScript())
    {
        rollbackSecurityUpdate();

        executeRemote(
            "rm -f " +
            shellQuote(SECURITY_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );

        return false;
    }


    // ========================================================
    // RESTART SERVICE
    // ========================================================

    std::cout
        << "[6/7] Restarting Security service...\n";

    output.clear();
    exitCode = -1;

    if (!executeRemote(
        "systemctl restart " +
        SECURITY_SERVICE,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Failed to restart Security service.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        rollbackSecurityUpdate();

        output.clear();
        exitCode = -1;

        executeRemote(
            "systemctl restart " +
            SECURITY_SERVICE,
            output,
            exitCode,
            true
        );

        return false;
    }


    // ========================================================
    // FINAL SERVICE CHECK
    // ========================================================

    std::cout
        << "[7/7] Checking Security service status...\n";

    if (!serviceIsActive())
    {
        std::cout
            << "[ERROR] Security service is not ACTIVE "
            "after update.\n";

        std::cout
            << "Starting rollback...\n";

        rollbackSecurityUpdate();

        output.clear();
        exitCode = -1;

        executeRemote(
            "systemctl restart " +
            SECURITY_SERVICE,
            output,
            exitCode,
            true
        );

        if (serviceIsActive())
        {
            std::cout
                << "[OK] Previous version restored "
                "and service is running.\n";
        }
        else
        {
            std::cout
                << "[ERROR] Previous version restored, "
                "but service is still not running.\n";
        }

        return false;
    }


    // ========================================================
    // CLEAN TEMP
    // ========================================================

    output.clear();
    exitCode = -1;

    executeRemote(
        "rm -f " +
        shellQuote(SECURITY_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );


    // ========================================================
    // SUCCESS
    // ========================================================

    sshSecurity = true;

    std::cout
        << "\n"
        << "========================================\n"
        << " SECURITY UPDATE SUCCESSFUL\n"
        << "========================================\n";

    std::cout
        << "Source:\n"
        << SECURITY_UPDATE_URL
        << "\n\n";

    std::cout
        << "Script:\n"
        << SECURITY_SCRIPT
        << "\n\n";

    std::cout
        << "Backup:\n"
        << SECURITY_BACKUP_SCRIPT
        << "\n\n";

    std::cout
        << "Service: ACTIVE\n";

    std::cout
        << "Protection: RUNNING\n";

    std::cout
        << "Runtime data: PRESERVED\n";

    std::cout
        << "========================================\n";

    return true;
}


// ============================================================
// SECURITY MENU
// ============================================================

void Security::menu()
{
    while (true)
    {
        std::cout
            << "\n"
            << "========================================\n"
            << " ServerGuard Security\n"
            << "========================================\n\n";

        std::cout
            << "1. Install / enable protection\n"
            << "2. Start protection\n"
            << "3. Stop protection\n"
            << "4. Disable automatic startup\n"
            << "5. Check status\n"
            << "6. Show logs\n"
            << "7. Update Security\n"
            << "0. Back\n\n";

        std::cout
            << "Select: ";

        std::string choice;

        std::getline(
            std::cin,
            choice
        );


        // ====================================================
        // INSTALL
        // ====================================================

        if (choice == "1")
        {
            installSecurity();

            continue;
        }


        // ====================================================
        // START
        // ====================================================

        if (choice == "2")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            if (!serviceExists())
            {
                std::cout
                    << "\n[ERROR] Security service "
                    "is not installed.\n";

                std::cout
                    << "Use option 1 first.\n";

                continue;
            }

            if (startService())
            {
                std::cout
                    << "\n[OK] Security protection started.\n";
            }
            else
            {
                std::cout
                    << "\n[ERROR] Failed to start "
                    "security protection.\n";
            }

            continue;
        }


        // ====================================================
        // STOP
        // ====================================================

        if (choice == "3")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            if (!serviceExists())
            {
                std::cout
                    << "\n[ERROR] Security service "
                    "is not installed.\n";

                continue;
            }

            if (stopService())
            {
                std::cout
                    << "\n[OK] Security protection stopped.\n";
            }
            else
            {
                std::cout
                    << "\n[ERROR] Failed to stop protection.\n";
            }

            continue;
        }


        // ====================================================
        // DISABLE STARTUP
        // ====================================================

        if (choice == "4")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            if (!serviceExists())
            {
                std::cout
                    << "\n[ERROR] Security service "
                    "is not installed.\n";

                continue;
            }

            if (disableService())
            {
                std::cout
                    << "\n[OK] Automatic startup disabled.\n";
            }
            else
            {
                std::cout
                    << "\n[ERROR] Failed to disable "
                    "automatic startup.\n";
            }

            continue;
        }


        // ====================================================
        // STATUS
        // ====================================================

        if (choice == "5")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            std::cout
                << "\n"
                << "----------------------------------------\n"
                << " ServerGuard Security Status\n"
                << "----------------------------------------\n";

            if (serviceExists())
            {
                std::cout
                    << "Service installed: YES\n";

                if (serviceIsActive())
                {
                    std::cout
                        << "Protection status: ACTIVE\n";
                }
                else
                {
                    std::cout
                        << "Protection status: INACTIVE\n";
                }

                std::string serviceOutput;
                int serviceExitCode = -1;

                if (executeRemote(
                    "systemctl is-enabled " +
                    SECURITY_SERVICE +
                    " 2>/dev/null",
                    serviceOutput,
                    serviceExitCode,
                    false))
                {
                    std::cout
                        << "Startup: "
                        << trim(serviceOutput)
                        << "\n";
                }
                else
                {
                    std::cout
                        << "Startup: disabled\n";
                }
            }
            else
            {
                sshSecurity = false;

                std::cout
                    << "Service installed: NO\n";

                std::cout
                    << "Protection status: NOT INSTALLED\n";
            }


            // ------------------------------------------------
            // SCRIPT
            // ------------------------------------------------

            std::string scriptOutput;
            int scriptExitCode = -1;

            if (executeRemote(
                "test -s " +
                shellQuote(SECURITY_SCRIPT),
                scriptOutput,
                scriptExitCode,
                false))
            {
                std::cout
                    << "Security script: INSTALLED\n";
            }
            else
            {
                std::cout
                    << "Security script: MISSING\n";
            }


            // ------------------------------------------------
            // UFW
            // ------------------------------------------------

            if (commandExists("ufw"))
            {
                std::cout
                    << "UFW installed: YES\n";

                std::string firewallOutput;
                int firewallExitCode = -1;

                if (executeRemote(
                    "ufw status verbose",
                    firewallOutput,
                    firewallExitCode,
                    true))
                {
                    std::cout
                        << "\nFirewall:\n"
                        << firewallOutput
                        << "\n";
                }
                else
                {
                    std::cout
                        << "UFW status: ERROR\n";
                }
            }
            else
            {
                std::cout
                    << "UFW installed: NO\n";
            }

            std::cout
                << "----------------------------------------\n";

            continue;
        }


        // ====================================================
        // LOGS
        // ====================================================

        if (choice == "6")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            if (!serviceExists())
            {
                std::cout
                    << "\n[ERROR] Security service "
                    "is not installed.\n";

                continue;
            }

            std::string output;
            int exitCode = -1;

            executeRemote(
                "journalctl -u " +
                SECURITY_SERVICE +
                " -n 100 --no-pager",
                output,
                exitCode,
                true
            );

            std::cout
                << "\n"
                << "========================================\n"
                << " Security logs\n"
                << "========================================\n\n";

            std::cout
                << output;

            std::cout
                << "\n========================================\n";

            continue;
        }


        // ====================================================
        // UPDATE SECURITY
        // ====================================================

        if (choice == "7")
        {
            std::cout
                << "\n"
                << "Update Security from GitHub?\n"
                << "\n"
                << "The current brute_force_guard.py "
                "will be backed up before replacement.\n"
                << "Runtime data in /opt/serverguard/data "
                "will NOT be changed.\n"
                << "The Security service will be restarted "
                "after the update.\n"
                << "\n"
                << "Source:\n"
                << SECURITY_UPDATE_URL
                << "\n"
                << "\n"
                << "Continue? [y/N]: ";

            std::string confirm;

            std::getline(
                std::cin,
                confirm
            );

            if (confirm == "y" ||
                confirm == "Y" ||
                confirm == "yes" ||
                confirm == "YES")
            {
                updateSecurity();
            }
            else
            {
                std::cout
                    << "Update cancelled.\n";
            }

            continue;
        }


        // ====================================================
        // BACK
        // ====================================================

        if (choice == "0")
        {
            break;
        }


        // ====================================================
        // UNKNOWN
        // ====================================================

        std::cout
            << "\nUnknown option.\n";
    }
}