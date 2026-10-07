#include "Security.h"

#include <libssh2.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cctype>

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

static const std::string SECURITY_UPDATE_URL =
"https://raw.githubusercontent.com/"
"Lukas6623/ServerGuard/main/brute_force_guard.py";

static const std::string SECURITY_BACKUP_DIR =
"/opt/serverguard/backups/security";

static const std::string SECURITY_BACKUP_SCRIPT =
"/opt/serverguard/backups/security/brute_force_guard.py";

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
        char* errorMessage = nullptr;

        libssh2_session_last_error(
            session,
            &errorMessage,
            nullptr,
            0
        );

        output =
            "Failed to open SSH channel.";

        if (errorMessage != nullptr)
        {
            output +=
                " libssh2: ";

            output +=
                errorMessage;
        }

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

            libssh2_channel_close(channel);
            libssh2_channel_free(channel);

            return false;
        }

        finalCommand =
            "sudo -S -p '' bash -c " +
            shellQuote(command);
    }
    else
    {
        finalCommand =
            command;
    }

    int execResult =
        libssh2_channel_exec(
            channel,
            finalCommand.c_str()
        );

    if (execResult != 0)
    {
        char* errorMessage = nullptr;

        libssh2_session_last_error(
            session,
            &errorMessage,
            nullptr,
            0
        );

        output =
            "Failed to execute remote command. "
            "libssh2 error: " +
            std::to_string(execResult);

        if (errorMessage != nullptr)
        {
            output +=
                " | ";

            output +=
                errorMessage;
        }

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

        ssize_t written =
            libssh2_channel_write(
                channel,
                passwordLine.c_str(),
                passwordLine.size()
            );

        if (written < 0)
        {
            output =
                "Failed to send sudo password.";

            libssh2_channel_close(channel);
            libssh2_channel_free(channel);

            return false;
        }
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
                    bytesRead
                    )
            );

            continue;
        }

        if (bytesRead == LIBSSH2_ERROR_EAGAIN)
        {
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

        char* errorMessage = nullptr;

        libssh2_session_last_error(
            session,
            &errorMessage,
            nullptr,
            0
        );

        output +=
            "\n[libssh2 channel read error: " +
            std::to_string(
                static_cast<int>(
                    bytesRead
                    )
            ) +
            "]";

        if (errorMessage != nullptr)
        {
            output +=
                " ";

            output +=
                errorMessage;
        }

        break;
    }

    libssh2_channel_send_eof(channel);

    libssh2_channel_wait_eof(channel);

    libssh2_channel_close(channel);

    libssh2_channel_wait_closed(channel);

    exitCode =
        libssh2_channel_get_exit_status(
            channel
        );

    libssh2_channel_free(channel);

    return exitCode == 0;
}

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

bool Security::installSecurity()
{
    std::cout
        << "\n"
        << "========================================\n"
        << " ServerGuard Security Installation\n"
        << "========================================\n\n";

    if (!checkRootOrSudo())
    {
        std::cout
            << "\n[ERROR] Administrator privileges "
            "are required.\n";

        return false;
    }

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

    if (!commandExists("curl"))
    {
        std::cout
            << "\ncurl is not installed.\n"
            << "Installing curl...\n";

        std::string output;
        int exitCode = -1;

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
                std::cout << output << "\n";
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
    else
    {
        std::cout
            << "[OK] curl is already installed.\n";
    }

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

    if (!commandExists("sshd"))
    {
        std::cout
            << "[ERROR] sshd is not available.\n";

        return false;
    }

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

    std::cout
        << "\nCreating ServerGuard directories...\n";

    if (!createDirectories())
    {
        return false;
    }

    std::cout
        << "[OK] Directories created.\n";

    std::cout
        << "\nChecking security script...\n";

    output.clear();
    exitCode = -1;

    bool scriptExists =
        executeRemote(
            "test -s " +
            shellQuote(SECURITY_SCRIPT),
            output,
            exitCode,
            false
        );

    if (scriptExists)
    {
        std::cout
            << "[OK] Security script already exists:\n"
            << SECURITY_SCRIPT
            << "\n";
    }
    else
    {
        std::cout
            << "Security script is missing.\n";

        std::cout
            << "Downloading brute_force_guard.py "
            "from GitHub...\n";

        output.clear();
        exitCode = -1;

        executeRemote(
            "rm -f " +
            shellQuote(SECURITY_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );

        output.clear();
        exitCode = -1;

        std::string downloadCommand =
            "curl -fL "
            "--connect-timeout 15 "
            "--max-time 120 "
            "--retry 2 "
            "-A " +
            shellQuote("ServerGuard/" + SECURITY_SERVICE) +
            " -o " +
            shellQuote(SECURITY_TEMP_SCRIPT) +
            " " +
            shellQuote(SECURITY_UPDATE_URL);

        if (!executeRemote(
            downloadCommand,
            output,
            exitCode,
            true))
        {
            std::cout
                << "[ERROR] Failed to download "
                "brute_force_guard.py from GitHub.\n";

            if (!output.empty())
            {
                std::cout
                    << output
                    << "\n";
            }

            return false;
        }

        std::cout
            << "[OK] Security script downloaded.\n";

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
                << "[ERROR] Downloaded security script "
                "is empty or missing.\n";

            executeRemote(
                "rm -f " +
                shellQuote(SECURITY_TEMP_SCRIPT),
                output,
                exitCode,
                true
            );

            return false;
        }

        std::cout
            << "Checking downloaded Python script...\n";

        output.clear();
        exitCode = -1;

        std::string syntaxCommand =
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
            syntaxCommand,
            output,
            exitCode,
            true))
        {
            std::cout
                << "[ERROR] Downloaded security script "
                "has invalid Python syntax.\n";

            if (!output.empty())
            {
                std::cout
                    << output
                    << "\n";
            }

            executeRemote(
                "rm -f " +
                shellQuote(SECURITY_TEMP_SCRIPT),
                output,
                exitCode,
                true
            );

            return false;
        }

        if (!output.empty())
        {
            std::cout
                << output;
        }

        std::cout
            << "Installing security script...\n";

        output.clear();
        exitCode = -1;

        std::string installCommand =
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
            installCommand,
            output,
            exitCode,
            true))
        {
            std::cout
                << "[ERROR] Failed to install "
                "security script.\n";

            if (!output.empty())
            {
                std::cout
                    << output
                    << "\n";
            }

            return false;
        }

        std::cout
            << "[OK] Security script installed:\n"
            << SECURITY_SCRIPT
            << "\n";
    }

    std::cout
        << "Verifying Security script...\n";

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
            << "[ERROR] Security script is missing after "
            "installation.\n";

        return false;
    }

    output.clear();
    exitCode = -1;

    std::string syntaxCheck =
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
        syntaxCheck,
        output,
        exitCode,
        true))
    {
        std::cout
            << "[ERROR] Installed Security script "
            "failed Python syntax verification.\n";

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

    if (!setFilePermissions())
    {
        return false;
    }

    std::cout
        << "[OK] Security script permissions configured.\n";

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

    if (!reloadSystemd())
    {
        return false;
    }

    std::cout
        << "[OK] systemd reloaded.\n";

    if (!enableService())
    {
        return false;
    }

    std::cout
        << "[OK] Automatic startup enabled.\n";

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

    sshSecurity = true;

    std::cout
        << "\n"
        << "========================================\n"
        << " ServerGuard Security ACTIVE\n"
        << "========================================\n\n";

    std::cout
        << "[OK] UFW firewall: ACTIVE\n";

    std::cout
        << "[OK] Security script: INSTALLED\n";

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

bool Security::isSSHSecurityEnabled() const
{
    return sshSecurity;
}

bool Security::downloadSecurityUpdate()
{
    std::cout
        << "\n"
        << "[1/7] Downloading new Security script...\n";

    std::string output;
    int exitCode = -1;

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

    if (!commandExists("python3"))
    {
        std::cout
            << "[ERROR] python3 is not installed.\n";

        return false;
    }

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

    if (!downloadSecurityUpdate())
    {
        return false;
    }

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

    output.clear();
    exitCode = -1;

    executeRemote(
        "rm -f " +
        shellQuote(SECURITY_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );

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

        if (choice == "1")
        {
            installSecurity();

            continue;
        }

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

        if (choice == "0")
        {
            break;
        }

        std::cout
            << "\nUnknown option.\n";
    }
}

static std::string securityJsonEscape(
    const std::string& value)
{
    std::string result;

    for (unsigned char c : value)
    {
        switch (c)
        {
        case '\"':
            result += "\\\"";
            break;

        case '\\':
            result += "\\\\";
            break;

        case '\b':
            result += "\\b";
            break;

        case '\f':
            result += "\\f";
            break;

        case '\n':
            result += "\\n";
            break;

        case '\r':
            result += "\\r";
            break;

        case '\t':
            result += "\\t";
            break;

        default:
            if (c < 0x20)
            {
                std::ostringstream ss;

                ss << "\\u"
                    << std::hex
                    << std::uppercase;

                const char* hex = "0123456789ABCDEF";

                ss << "00"
                    << hex[(c >> 4) & 0x0F]
                    << hex[c & 0x0F];

                result += ss.str();
            }
            else
            {
                result += static_cast<char>(c);
            }

            break;
        }
    }

    return result;
}

bool Security::webInstall()
{
    bool result = installSecurity();

    if (!result)
    {
        return false;
    }

    return serviceExists() &&
        serviceIsActive();
}

bool Security::webStart()
{
    if (!checkRootOrSudo())
    {
        return false;
    }

    if (!serviceExists())
    {
        return false;
    }

    if (!startService())
    {
        return false;
    }

    return serviceIsActive();
}

bool Security::webStop()
{
    if (!checkRootOrSudo())
    {
        return false;
    }

    if (!serviceExists())
    {
        return false;
    }

    if (!stopService())
    {
        return false;
    }

    return !serviceIsActive();
}

bool Security::webDisable()
{
    if (!checkRootOrSudo())
    {
        return false;
    }

    if (!serviceExists())
    {
        return false;
    }

    return disableService();
}

bool Security::webUpdate()
{
    return updateSecurity();
}

long long Security::webThreats()
{
    std::string output;
    int exitCode = -1;

    const std::string command =
        "if [ -f /opt/serverguard/data/stats.json ]; then "
        "cat /opt/serverguard/data/stats.json; "
        "else "
        "echo '{}'; "
        "fi";

    if (!executeRemote(
        command,
        output,
        exitCode,
        false
    ))
    {
        return 0;
    }

    output = trim(output);

    if (output.empty())
    {
        return 0;
    }

    const std::string key =
        "\"blocked\"";

    size_t keyPosition =
        output.find(key);

    if (keyPosition == std::string::npos)
    {
        return 0;
    }

    size_t colonPosition =
        output.find(
            ':',
            keyPosition + key.size()
        );

    if (colonPosition == std::string::npos)
    {
        return 0;
    }

    size_t numberStart =
        colonPosition + 1;

    while (
        numberStart < output.size() &&
        std::isspace(
            static_cast<unsigned char>(
                output[numberStart]
                )
        )
    {
        ++numberStart;
    }

    size_t numberEnd =
        numberStart;

    while (
        numberEnd < output.size() &&
        std::isdigit(
            static_cast<unsigned char>(
                output[numberEnd]
                )
        )
        )
    {
        ++numberEnd;
    }

    if (numberStart == numberEnd)
    {
        return 0;
    }

    try
    {
        return std::stoll(
            output.substr(
                numberStart,
                numberEnd - numberStart
            )
        );
    }
    catch (...)
    {
        return 0;
    }
}

std::string Security::webStatus()
{
    bool installed = serviceExists();

    bool active = false;
    bool enabled = false;

    if (installed)
    {
        active = serviceIsActive();

        std::string output;
        int exitCode = -1;

        enabled =
            executeRemote(
                "systemctl is-enabled " +
                SECURITY_SERVICE +
                " >/dev/null 2>&1",
                output,
                exitCode,
                false
            );
    }

    bool script = false;

    {
        std::string output;
        int exitCode = -1;

        script =
            executeRemote(
                "test -s " +
                shellQuote(SECURITY_SCRIPT),
                output,
                exitCode,
                false
            );
    }

    bool ufwInstalled =
        commandExists("ufw");

    bool ufwActive = false;

    if (ufwInstalled)
    {
        std::string output;
        int exitCode = -1;

        if (executeRemote(
            "ufw status | "
            "grep -q '^Status: active'",
            output,
            exitCode,
            false
        ))
        {
            ufwActive = true;
        }
        else
        {
            output.clear();
            exitCode = -1;

            ufwActive =
                executeRemote(
                    "ufw status | "
                    "grep -q '^Status: active'",
                    output,
                    exitCode,
                    true
                );
        }
    }

    std::vector<std::string> sshPorts;

    {
        std::string output;
        int exitCode = -1;

        bool result =
            executeRemote(
                "sshd -T 2>/dev/null | "
                "awk '$1 == \"port\" {print $2}'",
                output,
                exitCode,
                false
            );

        if (result)
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

                bool exists = false;

                for (const std::string& existing :
                    sshPorts)
                {
                    if (existing == port)
                    {
                        exists = true;
                        break;
                    }
                }

                if (!exists)
                {
                    sshPorts.push_back(port);
                }
            }
        }
    }

    std::ostringstream json;

    json
        << "{"

        << "\"installed\":"
        << (installed ? "true" : "false")

        << ",\"active\":"
        << (active ? "true" : "false")

        << ",\"enabled\":"
        << (enabled ? "true" : "false")

        << ",\"script\":"
        << (script ? "true" : "false")

        << ",\"ufwInstalled\":"
        << (ufwInstalled ? "true" : "false")

        << ",\"ufwActive\":"
        << (ufwActive ? "true" : "false")

        << ",\"service\":\""
        << securityJsonEscape(
            SECURITY_SERVICE)
        << "\""

        << ",\"scriptPath\":\""
        << securityJsonEscape(
            SECURITY_SCRIPT)
        << "\""

        << ",\"sshPorts\":[";

    for (size_t i = 0;
        i < sshPorts.size();
        ++i)
    {
        if (i > 0)
        {
            json << ",";
        }

        json
            << "\""
            << securityJsonEscape(
                sshPorts[i])
            << "\"";
    }

    json << "]";

    json << "}";

    return json.str();
}

std::string Security::webLogs()
{
    if (!serviceExists())
    {
        return "Security service is not installed.";
    }

    std::string output;
    int exitCode = -1;

    bool result =
        executeRemote(
            "journalctl -u " +
            SECURITY_SERVICE +
            " -n 100 --no-pager",
            output,
            exitCode,
            true
        );

    if (!result && output.empty())
    {
        return "Failed to get Security logs.";
    }

    return output;
}