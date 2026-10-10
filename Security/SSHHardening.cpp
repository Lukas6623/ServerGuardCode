#include "SSHHardening.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static const std::string SERVERGUARD_DIR = "/opt/serverguard";
static const std::string HARDENING_SCRIPT = "/opt/serverguard/ssh_hardening.py";
static const std::string SSH_CONFIG = "/etc/ssh/sshd_config";
static const std::string BACKUP_DIR = "/opt/serverguard/backups";
static const std::string HARDENING_CONFIG = "/etc/ssh/sshd_config.d/99-serverguard-hardening.conf";
static const std::string HARDENING_UPDATE_URL = "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/ssh_hardening.py";
static const std::string HARDENING_TEMP_SCRIPT = "/opt/serverguard/ssh_hardening.py.update";
static const std::string HARDENING_BACKUP_DIR = "/opt/serverguard/backups/ssh-hardening";
static const std::string HARDENING_BACKUP_SCRIPT = "/opt/serverguard/backups/ssh-hardening/ssh_hardening.py";
static const std::string HARDENING_CONFIG_BACKUP = "/opt/serverguard/backups/ssh-hardening/99-serverguard-hardening.conf";

static const std::string LINE = "============================================\n";

// ---------------------------------------------------------------- helpers

static std::string shellQuote(const std::string& value)
{
    std::string result = "'";
    for (char c : value)
    {
        if (c == '\'') result += "'\\''";
        else result += c;
    }
    return result + "'";
}

static void banner(const std::string& title)
{
    std::cout << "\n" << LINE << "  " << title << "\n" << LINE << "\n";
}

static void printIfNotEmpty(const std::string& text)
{
    if (!text.empty()) std::cout << text << "\n";
}

static std::string chmodChown(const std::string& path)
{
    return "chown root:root " + shellQuote(path) + " && chmod 755 " + shellQuote(path);
}

static std::string sshdValue(const std::string& output, const std::string& name)
{
    std::istringstream stream(output);
    std::string line;

    while (std::getline(stream, line))
    {
        std::istringstream lineStream(line);
        std::string key, value;
        lineStream >> key >> value;

        std::transform(key.begin(), key.end(), key.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (key == name) return value;
    }

    return "unknown";
}

static std::string jsonEscape(const std::string& text)
{
    std::string out;
    for (char c : text)
    {
        switch (c)
        {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

static std::string sessionError(LIBSSH2_SESSION* session, int& code)
{
    char* message = nullptr;
    int length = 0;
    code = libssh2_session_last_error(session, &message, &length, 0);
    return (message && length > 0) ? std::string(message, length) : std::string();
}

static void readChannel(LIBSSH2_CHANNEL* channel, std::string& output)
{
    char buffer[4096];

    while (true)
    {
        auto rc = libssh2_channel_read(channel, buffer, sizeof(buffer));

        if (rc > 0) output.append(buffer, static_cast<size_t>(rc));
        else if (rc == LIBSSH2_ERROR_EAGAIN || (rc == 0 && !libssh2_channel_eof(channel))) continue;
        else break;
    }
}

// ------------------------------------------------------------ constructor

SSHHardening::SSHHardening(LIBSSH2_SESSION* sshSession, const std::string& password, bool isKeyAuthentication)
{
    session = sshSession;
    sudoPassword = password;
    keyAuthentication = isKeyAuthentication;
    sudoRequired = false;
    sudoAuthenticated = false;
    hardeningEnabled = false;
}

// ------------------------------------------------------- remote execution

bool SSHHardening::executeRemote(const std::string& command, std::string& output, int& exitCode, bool useSudo)
{
    output.clear();
    exitCode = -1;

    if (!session)
    {
        output = "SSH session is invalid.";
        return false;
    }

    std::string finalCommand = command;

    if (useSudo && sudoRequired)
    {
        if (!sudoAuthenticated && !authenticateSudo())
        {
            output = "Cannot authenticate sudo.";
            return false;
        }
        finalCommand = "sudo -n bash -c " + shellQuote(command);
    }

    LIBSSH2_CHANNEL* channel = nullptr;

    while (!(channel = libssh2_channel_open_session(session)))
    {
        int code = 0;
        std::string message = sessionError(session, code);

        if (code == LIBSSH2_ERROR_EAGAIN) continue;

        output = "Cannot open SSH channel.";
        if (!message.empty()) output += "\nlibssh2 error: " + message;
        output += "\nlibssh2 error code: " + std::to_string(code);
        return false;
    }

    libssh2_channel_handle_extended_data2(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);

    int rc;
    while ((rc = libssh2_channel_exec(channel, finalCommand.c_str())) == LIBSSH2_ERROR_EAGAIN) {}

    if (rc != 0)
    {
        int code = 0;
        std::string message = sessionError(session, code);

        output = "Cannot execute remote command.";
        output += "\nlibssh2 channel_exec error code: " + std::to_string(rc);
        output += "\nlibssh2 session error code: " + std::to_string(code);
        if (!message.empty()) output += "\nlibssh2 error: " + message;
        output += "\nCommand: " + finalCommand;

        libssh2_channel_free(channel);
        return false;
    }

    readChannel(channel, output);

    libssh2_channel_send_eof(channel);
    libssh2_channel_wait_eof(channel);
    libssh2_channel_wait_closed(channel);

    exitCode = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);

    return exitCode == 0;
}

bool SSHHardening::authenticateSudo()
{
    if (!session) return false;

    if (!sudoRequired)
    {
        sudoAuthenticated = true;
        return true;
    }

    if (sudoPassword.empty())
    {
        std::cout << "Sudo password is empty.\n";
        return false;
    }

    std::cout << "Authenticating sudo...\n";

    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(session);

    if (!channel)
    {
        std::cout << "Cannot open SSH channel for sudo.\n";
        return false;
    }

    libssh2_channel_request_pty(channel, "xterm");
    libssh2_channel_handle_extended_data2(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);

    if (libssh2_channel_exec(channel, "sudo -S -p '' -v") != 0)
    {
        std::cout << "Cannot execute sudo.\n";
        libssh2_channel_free(channel);
        return false;
    }

    const std::string password = sudoPassword + "\n";
    size_t totalWritten = 0;

    while (totalWritten < password.size())
    {
        auto written = libssh2_channel_write(channel, password.c_str() + totalWritten, password.size() - totalWritten);

        if (written < 0 && written != LIBSSH2_ERROR_EAGAIN)
        {
            std::cout << "Cannot send sudo password.\n";
            libssh2_channel_free(channel);
            return false;
        }

        if (written > 0) totalWritten += static_cast<size_t>(written);
    }

    libssh2_channel_send_eof(channel);

    std::string output;
    readChannel(channel, output);

    libssh2_channel_wait_eof(channel);
    libssh2_channel_wait_closed(channel);

    int exitCode = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);

    sudoAuthenticated = (exitCode == 0);

    if (sudoAuthenticated)
    {
        std::cout << "Sudo authentication successful.\n";
        return true;
    }

    std::cout << "Sudo authentication failed.\n";
    printIfNotEmpty(output);
    return false;
}

// ------------------------------------------------------------- pre-checks

bool SSHHardening::commandExists(const std::string& command)
{
    std::string output;
    int exitCode = -1;
    executeRemote("command -v " + shellQuote(command) + " >/dev/null 2>&1", output, exitCode, false);
    return exitCode == 0;
}

bool SSHHardening::checkRootOrSudo()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("id -u", output, exitCode, false))
    {
        std::cout << "Cannot determine remote user.\n";
        return false;
    }

    output.erase(std::remove_if(output.begin(), output.end(),
        [](unsigned char c) { return std::isspace(c); }), output.end());

    if (output == "0")
    {
        sudoRequired = false;
        sudoAuthenticated = true;
        return true;
    }

    if (!commandExists("sudo"))
    {
        std::cout << "sudo is not installed.\n";
        return false;
    }

    sudoRequired = true;

    if (!authenticateSudo())
    {
        std::cout << "Current user cannot use sudo.\n";
        return false;
    }

    return true;
}

bool SSHHardening::checkScript()
{
    std::string output;
    int exitCode = -1;
    executeRemote("test -f " + shellQuote(HARDENING_SCRIPT), output, exitCode, false);
    return exitCode == 0;
}

bool SSHHardening::setPermissions()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(chmodChown(HARDENING_SCRIPT), output, exitCode, true))
    {
        std::cout << "Cannot configure script permissions.\n";
        printIfNotEmpty(output);
        return false;
    }

    return true;
}

// -------------------------------------------------------------- hardening

bool SSHHardening::runHardening()
{
    banner("APPLYING SSH HARDENING");

    std::string output;
    int exitCode = -1;

    const std::string authMethod = keyAuthentication ? "publickey" : "password";
    std::cout << "Authentication: " << (keyAuthentication ? "SSH private key" : "password") << "\n";

    const std::string command = "python3 " + shellQuote(HARDENING_SCRIPT) + " apply --auth-method=" + authMethod;

    std::cout << "Running SSH hardening pre-flight checks...\n";

    bool result = executeRemote(command, output, exitCode, true);
    printIfNotEmpty(output);

    if (!result)
    {
        std::cout << "\nSSH hardening failed.\nPython exit code: " << exitCode << "\n";
        hardeningEnabled = false;
        return false;
    }

    if (!checkHardening())
    {
        std::cout << "\nSSH hardening was not verified.\n";
        hardeningEnabled = false;
        return false;
    }

    hardeningEnabled = true;
    std::cout << "\nSSH hardening completed successfully.\n";
    return true;
}

bool SSHHardening::checkHardening()
{
    banner("SSH HARDENING STATUS");

    std::string output;
    int exitCode = -1;

    if (!executeRemote("sshd -T 2>/dev/null", output, exitCode, sudoRequired))
    {
        std::cout << "Cannot read effective SSH configuration.\n";
        hardeningEnabled = false;
        return false;
    }

    const std::vector<std::pair<std::string, std::string>> shown = {
        { "PermitRootLogin", "permitrootlogin" },
        { "PasswordAuthentication", "passwordauthentication" },
        { "PubkeyAuthentication", "pubkeyauthentication" },
        { "PermitEmptyPasswords", "permitemptypasswords" },
        { "MaxAuthTries", "maxauthtries" },
        { "LoginGraceTime", "logingracetime" },
        { "X11Forwarding", "x11forwarding" },
        { "AllowTcpForwarding", "allowtcpforwarding" },
        { "AllowAgentForwarding", "allowagentforwarding" },
        { "Compression", "compression" } };

    for (const auto& [label, key] : shown)
        std::cout << label << ": " << sshdValue(output, key) << "\n";

    // name, sshd key, expected value
    const std::vector<std::vector<std::string>> checks = {
        { "PermitEmptyPasswords", "permitemptypasswords", "no" },
        { "MaxAuthTries", "maxauthtries", "3" },
        { "LoginGraceTime", "logingracetime", "30" },
        { "X11Forwarding", "x11forwarding", "no" },
        { "AllowAgentForwarding", "allowagentforwarding", "no" },
        { "Compression", "compression", "no" } };

    bool allGood = true;
    std::cout << "\nVerification:\n";

    for (const auto& c : checks)
    {
        const std::string actual = sshdValue(output, c[1]);

        if (actual == c[2])
        {
            std::cout << "[OK] " << c[0] << " = " << actual << "\n";
        }
        else
        {
            std::cout << "[FAIL] " << c[0] << " = " << actual << " (expected " << c[2] << ")\n";
            allGood = false;
        }
    }

    if (checkSSHService())
    {
        std::cout << "\nSSH service: ACTIVE\n";
    }
    else
    {
        std::cout << "\nSSH service: NOT ACTIVE\n";
        allGood = false;
    }

    std::cout << "\n" << LINE << "ServerGuard hardening: " << (allGood ? "ENABLED" : "NOT ENABLED") << "\n" << LINE;

    hardeningEnabled = allGood;
    return allGood;
}

bool SSHHardening::checkSSHService()
{
    std::string output;
    int exitCode = -1;

    executeRemote("systemctl is-active --quiet ssh", output, exitCode, false);
    if (exitCode == 0) return true;

    executeRemote("systemctl is-active --quiet sshd", output, exitCode, false);
    return exitCode == 0;
}

bool SSHHardening::isSSHConfigValid()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("sshd -t", output, exitCode, true))
    {
        printIfNotEmpty(output);
        return false;
    }

    return true;
}

// ---------------------------------------------------------------- backups

bool SSHHardening::showBackups()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("ls -lah " + shellQuote(BACKUP_DIR) + " 2>/dev/null", output, exitCode, sudoRequired))
    {
        std::cout << "Cannot read backup directory.\n";
        return false;
    }

    banner("SSH BACKUPS");

    if (output.empty()) std::cout << "No backups found.\n";
    else std::cout << output << "\n";

    return true;
}

bool SSHHardening::restoreConfiguration()
{
    std::cout << "\n";
    showBackups();

    std::cout << "\nEnter backup filename (empty to cancel): ";

    std::string filename;
    std::getline(std::cin >> std::ws, filename);

    while (!filename.empty() && std::isspace(static_cast<unsigned char>(filename.back())))
        filename.pop_back();

    if (filename.empty()) return false;

    if (filename.find('/') != std::string::npos ||
        filename.find('\\') != std::string::npos ||
        filename.find("..") != std::string::npos)
    {
        std::cout << "Invalid backup filename.\n";
        return false;
    }

    const std::string prefix = "pre-hardening_";
    const std::string suffix = ".tar.gz";

    if (filename.size() <= prefix.size() + suffix.size() ||
        filename.compare(0, prefix.size(), prefix) != 0 ||
        filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) != 0)
    {
        std::cout << "Unsupported backup type. Expected: pre-hardening_*.tar.gz\n";
        return false;
    }

    if (!checkRootOrSudo()) return false;

    if (!checkScript())
    {
        std::cout << "SSH Hardening script was not found:\n" << HARDENING_SCRIPT << "\n";
        return false;
    }

    const std::string backupPath = BACKUP_DIR + "/" + filename;
    std::string output;
    int exitCode = -1;

    // The backups directory is root-only, so the check goes through sudo.
    if (!executeRemote("test -f " + shellQuote(backupPath) + " && test -f " + shellQuote(backupPath + ".json"),
        output, exitCode, true))
    {
        std::cout << "Backup file (or its .json manifest) not found.\n";
        return false;
    }

    std::cout << "\nRestoring configuration...\n";

    bool ok = executeRemote("python3 " + shellQuote(HARDENING_SCRIPT) + " restore " + shellQuote(filename),
        output, exitCode, true);

    if (!output.empty()) std::cout << "\n" << output << "\n";

    if (!ok)
    {
        std::cout << "\nCannot restore configuration.\nPython exit code: " << exitCode << "\n";
        return false;
    }

    std::cout << "\nSSH configuration restored successfully.\n";
    checkHardening();
    return true;
}

// ----------------------------------------------------------------- update

bool SSHHardening::downloadUpdate()
{
    std::cout << "\n[1/6] Downloading new SSH Hardening script...\n";

    std::string output;
    int exitCode = -1;

    const std::string cleanup = "rm -f " + shellQuote(HARDENING_TEMP_SCRIPT);
    executeRemote(cleanup, output, exitCode, true);

    const std::string command =
        "curl -fL --connect-timeout 15 --max-time 120 --retry 2 -o " +
        shellQuote(HARDENING_TEMP_SCRIPT) + " " + shellQuote(HARDENING_UPDATE_URL);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Download failed.\n";
        printIfNotEmpty(output);
        executeRemote(cleanup, output, exitCode, true);
        return false;
    }

    if (!executeRemote("test -s " + shellQuote(HARDENING_TEMP_SCRIPT), output, exitCode, false))
    {
        std::cout << "Downloaded file is empty.\n";
        executeRemote(cleanup, output, exitCode, true);
        return false;
    }

    std::cout << "Download completed.\n";
    return true;
}

bool SSHHardening::verifyUpdate()
{
    std::cout << "[2/6] Checking Python syntax...\n";

    const std::string pythonCommand =
        "import ast,sys;"
        "p=open(sys.argv[1],encoding='utf-8').read();"
        "ast.parse(p,filename=sys.argv[1]);"
        "print('Python syntax: OK')";

    std::string output;
    int exitCode = -1;

    if (!executeRemote("python3 -c " + shellQuote(pythonCommand) + " " + shellQuote(HARDENING_TEMP_SCRIPT),
        output, exitCode, false))
    {
        std::cout << "Python syntax verification FAILED.\n";
        printIfNotEmpty(output);
        return false;
    }

    std::cout << output;

    if (!executeRemote("test -s " + shellQuote(HARDENING_TEMP_SCRIPT), output, exitCode, false))
    {
        std::cout << "Downloaded script is invalid.\n";
        return false;
    }

    std::cout << "Checking current SSH configuration...\n";

    if (!isSSHConfigValid())
    {
        std::cout << "Current SSH configuration is invalid.\nUpdate cancelled.\n";
        return false;
    }

    std::cout << "Update verification completed.\n";
    return true;
}

bool SSHHardening::backupCurrentScript()
{
    std::cout << "[3/6] Creating backup of current SSH Hardening script...\n";

    std::string output;
    int exitCode = -1;

    if (!executeRemote("test -f " + shellQuote(HARDENING_SCRIPT), output, exitCode, false))
    {
        std::cout << "Current SSH Hardening script not found.\n";
        return false;
    }

    if (!executeRemote("mkdir -p " + shellQuote(HARDENING_BACKUP_DIR), output, exitCode, true))
    {
        std::cout << "Cannot create backup directory.\n";
        printIfNotEmpty(output);
        return false;
    }

    if (!executeRemote("cp -p " + shellQuote(HARDENING_SCRIPT) + " " + shellQuote(HARDENING_BACKUP_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Cannot create backup.\n";
        printIfNotEmpty(output);
        return false;
    }

    executeRemote(chmodChown(HARDENING_BACKUP_SCRIPT), output, exitCode, true);

    std::cout << "Backup created:\n" << HARDENING_BACKUP_SCRIPT << "\n";
    return true;
}

bool SSHHardening::installUpdatedScript()
{
    std::cout << "[4/6] Installing new SSH Hardening script...\n";

    std::string output;
    int exitCode = -1;

    if (!executeRemote("mv -f " + shellQuote(HARDENING_TEMP_SCRIPT) + " " + shellQuote(HARDENING_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Cannot replace SSH Hardening script.\n";
        printIfNotEmpty(output);
        return false;
    }

    if (!executeRemote(chmodChown(HARDENING_SCRIPT), output, exitCode, true))
    {
        std::cout << "Cannot configure updated script permissions.\n";
        return false;
    }

    return true;
}

bool SSHHardening::rollbackUpdate()
{
    std::cout << "\n" << LINE << "       ROLLING BACK SSH HARDENING\n" << LINE;

    std::string output;
    int exitCode = -1;

    if (!executeRemote("test -f " + shellQuote(HARDENING_BACKUP_SCRIPT), output, exitCode, false))
    {
        std::cout << "Backup file not found.\n";
        return false;
    }

    if (!executeRemote("cp -p " + shellQuote(HARDENING_BACKUP_SCRIPT) + " " + shellQuote(HARDENING_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Cannot restore previous script.\n";
        return false;
    }

    executeRemote(chmodChown(HARDENING_SCRIPT), output, exitCode, true);
    executeRemote("rm -f " + shellQuote(HARDENING_TEMP_SCRIPT), output, exitCode, true);

    if (!isSSHConfigValid())
    {
        std::cout << "Previous script restored, but SSH configuration is still invalid.\n";
        return false;
    }

    std::cout << "\nRollback successful.\nPrevious SSH Hardening script restored.\n";
    return true;
}

bool SSHHardening::update()
{
    banner("UPDATE SSH HARDENING");

    std::string output;
    int exitCode = -1;

    const auto removeTemp = [&] { executeRemote("rm -f " + shellQuote(HARDENING_TEMP_SCRIPT), output, exitCode, true); };

    if (!checkRootOrSudo()) return false;

    if (!checkScript())
    {
        std::cout << "SSH Hardening script is not installed:\n" << HARDENING_SCRIPT << "\n";
        return false;
    }

    if (!commandExists("python3"))
    {
        std::cout << "python3 is not installed.\n";
        return false;
    }

    if (!commandExists("curl"))
    {
        std::cout << "curl is not installed.\nInstalling curl...\n";

        if (!executeRemote("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl",
            output, exitCode, true))
        {
            std::cout << "Cannot install curl.\n";
            printIfNotEmpty(output);
            return false;
        }
    }

    if (!downloadUpdate()) return false;

    if (!verifyUpdate())
    {
        std::cout << "\nUpdate cancelled.\nCurrent SSH Hardening script was not changed.\n";
        removeTemp();
        return false;
    }

    if (!backupCurrentScript())
    {
        removeTemp();
        return false;
    }

    if (!installUpdatedScript())
    {
        std::cout << "\nNew SSH Hardening script was not installed.\n";
        removeTemp();
        return false;
    }

    std::cout << "[5/6] Verifying installed SSH Hardening script...\n";

    const std::string pythonCommand =
        "import ast;"
        "p=open('/opt/serverguard/ssh_hardening.py',encoding='utf-8').read();"
        "ast.parse(p,filename='ssh_hardening.py');"
        "print('Installed script: OK')";

    if (!executeRemote("python3 -c " + shellQuote(pythonCommand), output, exitCode, false))
    {
        std::cout << "Installed script verification failed.\n";
        rollbackUpdate();
        return false;
    }

    std::cout << output;
    std::cout << "[6/6] Final SSH configuration validation...\n";

    if (!isSSHConfigValid())
    {
        std::cout << "\nSSH configuration validation failed.\nStarting automatic rollback...\n";

        if (!rollbackUpdate())
            std::cout << "WARNING: rollback also failed.\nCheck SSH configuration manually.\n";

        return false;
    }

    removeTemp();

    std::cout << "\n" << LINE << "   SSH HARDENING UPDATE SUCCESSFUL\n" << LINE
        << "Source:\n" << HARDENING_UPDATE_URL << "\n\n"
        << "Script:\n" << HARDENING_SCRIPT << "\n\n"
        << "Backup:\n" << HARDENING_BACKUP_SCRIPT << "\n\n"
        << "SSH configuration: VALID\n" << LINE;

    return true;
}

// ------------------------------------------------------------------- menu

void SSHHardening::menu()
{
    while (true)
    {
        std::cout << "\n" << LINE << "             SSH HARDENING\n" << LINE
            << "\n"
            << "1. Apply hardening\n"
            << "2. Check hardening status\n"
            << "3. Disable hardening\n"
            << "4. Show SSH configuration\n"
            << "5. Restore backup\n"
            << "6. Install / update hardening script\n"
            << "0. Back\n"
            << "\nSelect: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "0") return;

        if (choice == "1")
        {
            if (!webApply()) std::cout << "\nSSH hardening was not applied.\n\n";
            continue;
        }

        if (choice == "2")
        {
            if (checkRootOrSudo()) checkHardening();
            continue;
        }

        if (choice == "3")
        {
            if (!checkRootOrSudo()) continue;

            if (!checkScript())
            {
                std::cout << "\nSSH hardening script was not found:\n" << HARDENING_SCRIPT << "\n\n";
                continue;
            }

            std::cout << "\nDisabling SSH hardening...\n";

            std::string output;
            int exitCode = -1;

            if (!executeRemote("python3 " + shellQuote(HARDENING_SCRIPT) + " disable", output, exitCode, true))
            {
                std::cout << "\nCannot execute remote command.\n";
                continue;
            }

            if (!output.empty()) std::cout << "\n" << output << "\n";

            if (exitCode != 0)
            {
                std::cout << "\nSSH hardening disable failed.\nPython exit code: " << exitCode << "\n";
                continue;
            }

            hardeningEnabled = false;
            std::cout << "\nSSH hardening disabled successfully.\n";
            continue;
        }

        if (choice == "4")
        {
            if (!checkRootOrSudo()) continue;

            std::string output;
            int exitCode = -1;

            if (!executeRemote("sshd -T 2>/dev/null", output, exitCode, true) || exitCode != 0)
            {
                std::cout << "\nCannot read SSH configuration.\n";
                printIfNotEmpty(output);
                continue;
            }

            banner("EFFECTIVE SSH CONFIGURATION");

            static const std::vector<std::string> keys = {
                "permitrootlogin ", "permitemptypasswords ", "pubkeyauthentication ",
                "passwordauthentication ", "kbdinteractiveauthentication ", "maxauthtries ",
                "logingracetime ", "x11forwarding ", "allowtcpforwarding ",
                "allowagentforwarding ", "compression " };

            std::istringstream stream(output);
            std::string line;

            while (std::getline(stream, line))
            {
                for (const auto& key : keys)
                {
                    if (line.rfind(key, 0) == 0)
                    {
                        std::cout << line << "\n";
                        break;
                    }
                }
            }

            std::cout << "\n";
            continue;
        }

        if (choice == "5")
        {
            restoreConfiguration();
            continue;
        }

        if (choice == "6")
        {
            if (!checkRootOrSudo()) continue;

            if (!checkScript())
            {
                std::cout << "\nSSH hardening script was not found:\n" << HARDENING_SCRIPT << "\n\n"
                    << "Use the Web API or the existing installation mechanism to install the script.\n";
                continue;
            }

            std::cout << "\nSSH hardening script is already installed:\n" << HARDENING_SCRIPT << "\n";
            continue;
        }

        std::cout << "\nInvalid option.\n";
    }
}

bool SSHHardening::isEnabled() const
{
    return hardeningEnabled;
}

// ------------------------------------------------------------- web API

bool SSHHardening::webInstall()
{
    banner("INSTALL SSH HARDENING");

    if (!checkRootOrSudo()) return false;

    if (!commandExists("python3"))
    {
        std::cout << "python3 is not installed.\n";
        return false;
    }

    std::string output;
    int exitCode = -1;

    const auto removeTemp = [&] { executeRemote("rm -f " + shellQuote(HARDENING_TEMP_SCRIPT), output, exitCode, true); };

    if (!executeRemote("mkdir -p " + shellQuote(SERVERGUARD_DIR), output, exitCode, true))
    {
        std::cout << "Cannot create ServerGuard directory.\n";
        printIfNotEmpty(output);
        return false;
    }

    if (!commandExists("curl"))
    {
        std::cout << "curl is not installed.\nInstalling curl...\n";

        if (!executeRemote("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl",
            output, exitCode, true))
        {
            std::cout << "Cannot install curl.\n";
            printIfNotEmpty(output);
            return false;
        }
    }

    if (checkScript())
    {
        std::cout << "SSH Hardening script is already installed.\n";
        return true;
    }

    if (!downloadUpdate()) return false;

    std::cout << "Verifying downloaded SSH Hardening script...\n";

    if (!verifyUpdate())
    {
        std::cout << "Downloaded SSH Hardening script failed verification.\n";
        removeTemp();
        return false;
    }

    if (!installUpdatedScript())
    {
        std::cout << "Cannot install SSH Hardening script.\n";
        removeTemp();
        return false;
    }

    if (!checkScript())
    {
        std::cout << "SSH Hardening installation verification failed.\n";
        return false;
    }

    removeTemp();

    std::cout << "\n" << LINE << "   SSH HARDENING INSTALLATION SUCCESSFUL\n" << LINE
        << "Script:\n" << HARDENING_SCRIPT << "\n\n"
        << "SSH configuration was NOT changed.\n"
        << "Use Apply Hardening to apply the configuration.\n" << LINE;

    return true;
}

bool SSHHardening::webRemove()
{
    banner("REMOVE SSH HARDENING");

    if (!checkRootOrSudo()) return false;

    std::string output;
    int exitCode = -1;

    const std::string restoreCommand =
        "if [ -f " + shellQuote(HARDENING_CONFIG_BACKUP) + " ]; then cp -p " +
        shellQuote(HARDENING_CONFIG_BACKUP) + " " + shellQuote(HARDENING_CONFIG) + "; fi";

    if (!executeRemote("mkdir -p " + shellQuote(HARDENING_BACKUP_DIR), output, exitCode, true))
    {
        std::cout << "Cannot create hardening backup directory.\n";
        return false;
    }

    executeRemote("rm -f " + shellQuote(HARDENING_CONFIG_BACKUP), output, exitCode, true);

    const std::string backupCommand =
        "if [ -f " + shellQuote(HARDENING_CONFIG) + " ]; then cp -p " +
        shellQuote(HARDENING_CONFIG) + " " + shellQuote(HARDENING_CONFIG_BACKUP) + "; fi";

    if (!executeRemote(backupCommand, output, exitCode, true))
    {
        std::cout << "Cannot backup SSH Hardening configuration.\n";
        return false;
    }

    std::cout << "Removing ServerGuard SSH configuration...\n";

    if (!executeRemote("rm -f " + shellQuote(HARDENING_CONFIG), output, exitCode, true))
    {
        std::cout << "Cannot remove SSH Hardening configuration.\n";
        return false;
    }

    std::cout << "Validating SSH configuration...\n";

    if (!isSSHConfigValid())
    {
        std::cout << "\nSSH configuration became invalid after removal.\n"
            << "Restoring ServerGuard hardening configuration...\n";

        executeRemote(restoreCommand, output, exitCode, true);

        if (isSSHConfigValid()) std::cout << "SSH Hardening configuration restored.\n";
        else std::cout << "WARNING: SSH configuration could not be automatically restored.\n";

        return false;
    }

    std::cout << "Removing SSH Hardening script...\n";

    if (!executeRemote("rm -f " + shellQuote(HARDENING_SCRIPT) + " " + shellQuote(HARDENING_TEMP_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Cannot remove SSH Hardening script.\n";
        executeRemote(restoreCommand, output, exitCode, true);
        return false;
    }

    if (executeRemote("test -f " + shellQuote(HARDENING_SCRIPT), output, exitCode, false))
    {
        std::cout << "SSH Hardening script still exists.\n";
        return false;
    }

    if (!isSSHConfigValid())
    {
        std::cout << "Final SSH configuration validation failed.\n";
        return false;
    }

    std::cout << "Reloading SSH service...\n";

    if (!executeRemote("systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null",
        output, exitCode, true))
    {
        std::cout << "SSH reload failed.\n";
        return false;
    }

    hardeningEnabled = false;

    std::cout << "\n" << LINE << "     SSH HARDENING REMOVED SUCCESSFULLY\n" << LINE
        << "Script removed:\n" << HARDENING_SCRIPT << "\n\n"
        << "ServerGuard configuration removed:\n" << HARDENING_CONFIG << "\n\n"
        << "Backup:\n" << HARDENING_CONFIG_BACKUP << "\n\n"
        << "Main SSH configuration was NOT deleted.\n"
        << "SSH configuration: VALID\n" << LINE;

    return true;
}

bool SSHHardening::webApply()
{
    if (!keyAuthentication)
    {
        std::cout << "\n" << LINE << "       SSH HARDENING SAFETY CHECK\n" << LINE
            << "\n"
            << "[FAIL] ServerGuard is connected using password authentication.\n"
            << "[FAIL] SSH hardening was blocked for safety.\n"
            << "[INFO] Password authentication will NOT be disabled.\n"
            << "[INFO] Connect to the server using an SSH private key first.\n\n";
        return false;
    }

    if (!checkRootOrSudo()) return false;

    if (!checkScript())
    {
        std::cout << "SSH Hardening script was not found:\n" << HARDENING_SCRIPT << "\n";
        return false;
    }

    return setPermissions() && runHardening();
}

bool SSHHardening::webValidate()
{
    return checkRootOrSudo() && isSSHConfigValid();
}

bool SSHHardening::webUpdate()
{
    return update();
}

std::string SSHHardening::webStatus()
{
    std::string output;
    int exitCode = -1;

    const bool sshActive = checkSSHService();

    std::string permitRootLogin = "unknown", permitEmptyPasswords = "unknown", maxAuthTries = "unknown",
        loginGraceTime = "unknown", x11Forwarding = "unknown", allowTcpForwarding = "unknown",
        allowAgentForwarding = "unknown", compression = "unknown";

    if (sshActive && executeRemote("sshd -T 2>/dev/null", output, exitCode, sudoRequired))
    {
        permitRootLogin = sshdValue(output, "permitrootlogin");
        permitEmptyPasswords = sshdValue(output, "permitemptypasswords");
        maxAuthTries = sshdValue(output, "maxauthtries");
        loginGraceTime = sshdValue(output, "logingracetime");
        x11Forwarding = sshdValue(output, "x11forwarding");
        allowTcpForwarding = sshdValue(output, "allowtcpforwarding");
        allowAgentForwarding = sshdValue(output, "allowagentforwarding");
        compression = sshdValue(output, "compression");
    }

    const bool realHardening =
        sshActive && permitEmptyPasswords == "no" && maxAuthTries == "3" && loginGraceTime == "30" &&
        x11Forwarding == "no" && allowAgentForwarding == "no" && compression == "no";

    hardeningEnabled = realHardening;

    const auto b = [](bool v) { return v ? "true" : "false"; };
    const auto s = [](const std::string& k, const std::string& v) { return ",\"" + k + "\":\"" + jsonEscape(v) + "\""; };

    std::ostringstream json;
    json << "{\"installed\":" << b(checkScript())
        << ",\"enabled\":" << b(realHardening)
        << ",\"sshActive\":" << b(sshActive)
        << ",\"configValid\":" << b(isSSHConfigValid())
        << s("scriptPath", HARDENING_SCRIPT)
        << s("configPath", SSH_CONFIG)
        << s("hardeningConfig", HARDENING_CONFIG)
        << s("permitRootLogin", permitRootLogin)
        << s("permitEmptyPasswords", permitEmptyPasswords)
        << s("maxAuthTries", maxAuthTries)
        << s("loginGraceTime", loginGraceTime)
        << s("x11Forwarding", x11Forwarding)
        << s("allowTcpForwarding", allowTcpForwarding)
        << s("allowAgentForwarding", allowAgentForwarding)
        << s("compression", compression)
        << "}";

    return json.str();
}

std::string SSHHardening::webBackups()
{
    std::string output;
    int exitCode = -1;

    executeRemote("ls -lah " + shellQuote(BACKUP_DIR) + " 2>/dev/null", output, exitCode, sudoRequired);

    std::ostringstream json;
    json << "{\"ok\":" << (exitCode == 0 ? "true" : "false")
        << ",\"path\":\"" << jsonEscape(BACKUP_DIR) << "\""
        << ",\"text\":\"" << jsonEscape(output) << "\"}";

    return json.str();
}