#include "SSHHardening.h"

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>


static const std::string SERVERGUARD_DIR =
"/opt/serverguard";

static const std::string HARDENING_SCRIPT =
"/opt/serverguard/ssh_hardening.py";

static const std::string SSH_CONFIG =
"/etc/ssh/sshd_config";

static const std::string BACKUP_DIR =
"/opt/serverguard/backups";


static const std::string HARDENING_CONFIG =
"/etc/ssh/sshd_config.d/99-serverguard-hardening.conf";


static const std::string HARDENING_UPDATE_URL =
"https://raw.githubusercontent.com/"
"Lukas6623/ServerGuard/main/ssh_hardening.py";

static const std::string HARDENING_TEMP_SCRIPT =
"/opt/serverguard/ssh_hardening.py.update";

static const std::string HARDENING_BACKUP_DIR =
"/opt/serverguard/backups/ssh-hardening";

static const std::string HARDENING_BACKUP_SCRIPT =
"/opt/serverguard/backups/ssh-hardening/ssh_hardening.py";


static const std::string HARDENING_CONFIG_BACKUP =
"/opt/serverguard/backups/ssh-hardening/99-serverguard-hardening.conf";


static std::string shellQuote(
    const std::string& value
)
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


SSHHardening::SSHHardening(
    LIBSSH2_SESSION* sshSession,
    const std::string& password,
    bool isKeyAuthentication
)
{
    session = sshSession;

    sudoPassword = password;

    keyAuthentication = isKeyAuthentication;

    sudoRequired = false;

    sudoAuthenticated = false;

    hardeningEnabled = false;
}


bool SSHHardening::executeRemote(
    const std::string& command,
    std::string& output,
    int& exitCode,
    bool useSudo
)
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
        if (!sudoAuthenticated)
        {
            if (!authenticateSudo())
            {
                output = "Cannot authenticate sudo.";

                return false;
            }
        }

        finalCommand =
            "sudo -n bash -c " +
            shellQuote(command);
    }


    LIBSSH2_CHANNEL* channel = nullptr;

    while (true)
    {
        channel =
            libssh2_channel_open_session(
                session
            );

        if (channel)
        {
            break;
        }


        int lastError = 0;

        char* errorMessage = nullptr;

        int errorLength = 0;

        lastError =
            libssh2_session_last_error(
                session,
                &errorMessage,
                &errorLength,
                0
            );


        if (lastError == LIBSSH2_ERROR_EAGAIN)
        {
            continue;
        }


        output =
            "Cannot open SSH channel.";

        if (errorMessage && errorLength > 0)
        {
            output +=
                "\nlibssh2 error: " +
                std::string(
                    errorMessage,
                    errorLength
                );
        }

        output +=
            "\nlibssh2 error code: " +
            std::to_string(lastError);


        return false;
    }


    libssh2_channel_handle_extended_data2(
        channel,
        LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
    );


    while (true)
    {
        int rc =
            libssh2_channel_exec(
                channel,
                finalCommand.c_str()
            );


        if (rc == 0)
        {
            break;
        }


        if (rc == LIBSSH2_ERROR_EAGAIN)
        {
            continue;
        }


        char* errorMessage = nullptr;

        int errorLength = 0;

        int lastError =
            libssh2_session_last_error(
                session,
                &errorMessage,
                &errorLength,
                0
            );


        output =
            "Cannot execute remote command.";

        output +=
            "\nlibssh2 channel_exec error code: " +
            std::to_string(rc);

        output +=
            "\nlibssh2 session error code: " +
            std::to_string(lastError);


        if (errorMessage && errorLength > 0)
        {
            output +=
                "\nlibssh2 error: " +
                std::string(
                    errorMessage,
                    errorLength
                );
        }


        output +=
            "\nCommand: " +
            finalCommand;


        libssh2_channel_free(channel);

        return false;
    }


    char buffer[4096];


    while (true)
    {
        int rc =
            static_cast<int>(
                libssh2_channel_read(
                    channel,
                    buffer,
                    sizeof(buffer) - 1
                )
                );


        if (rc > 0)
        {
            buffer[rc] = '\0';

            output += buffer;

            continue;
        }


        if (rc == 0)
        {
            if (libssh2_channel_eof(channel))
            {
                break;
            }

            continue;
        }


        if (rc == LIBSSH2_ERROR_EAGAIN)
        {
            continue;
        }


        break;
    }


    libssh2_channel_send_eof(channel);

    libssh2_channel_wait_eof(channel);

    libssh2_channel_wait_closed(channel);


    exitCode =
        libssh2_channel_get_exit_status(
            channel
        );


    libssh2_channel_free(channel);


    return exitCode == 0;
}


bool SSHHardening::authenticateSudo()
{
    if (!session)
    {
        return false;
    }


    if (!sudoRequired)
    {
        sudoAuthenticated = true;

        return true;
    }


    if (sudoPassword.empty())
    {
        std::cout
            << "Sudo password is empty.\n";

        return false;
    }


    std::cout
        << "Authenticating sudo...\n";


    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(
            session
        );


    if (!channel)
    {
        std::cout
            << "Cannot open SSH channel for sudo.\n";

        return false;
    }


    libssh2_channel_request_pty(
        channel,
        "xterm"
    );


    libssh2_channel_handle_extended_data2(
        channel,
        LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
    );


    const char* command =
        "sudo -S -p '' -v";


    if (libssh2_channel_exec(
        channel,
        command
    ) != 0)
    {
        std::cout
            << "Cannot execute sudo.\n";

        libssh2_channel_free(channel);

        return false;
    }


    std::string password =
        sudoPassword + "\n";


    size_t totalWritten = 0;


    while (totalWritten < password.size())
    {
        int written =
            static_cast<int>(
                libssh2_channel_write(
                    channel,
                    password.c_str() + totalWritten,
                    password.size() - totalWritten
                )
                );


        if (written < 0)
        {
            std::cout
                << "Cannot send sudo password.\n";

            libssh2_channel_free(channel);

            return false;
        }


        if (written == 0)
        {
            continue;
        }


        totalWritten +=
            static_cast<size_t>(
                written
                );
    }


    libssh2_channel_send_eof(channel);


    char buffer[4096];

    std::string output;


    while (true)
    {
        int rc =
            static_cast<int>(
                libssh2_channel_read(
                    channel,
                    buffer,
                    sizeof(buffer) - 1
                )
                );


        if (rc > 0)
        {
            buffer[rc] = '\0';

            output += buffer;

            continue;
        }


        if (rc == 0)
        {
            if (libssh2_channel_eof(channel))
            {
                break;
            }

            continue;
        }


        if (rc == LIBSSH2_ERROR_EAGAIN)
        {
            continue;
        }


        break;
    }


    libssh2_channel_wait_eof(channel);

    libssh2_channel_wait_closed(channel);


    int exitCode =
        libssh2_channel_get_exit_status(
            channel
        );


    libssh2_channel_free(channel);


    if (exitCode == 0)
    {
        sudoAuthenticated = true;

        std::cout
            << "Sudo authentication successful.\n";

        return true;
    }


    sudoAuthenticated = false;


    std::cout
        << "Sudo authentication failed.\n";


    if (!output.empty())
    {
        std::cout
            << output
            << "\n";
    }


    return false;
}


bool SSHHardening::commandExists(
    const std::string& command
)
{
    std::string output;

    int exitCode = -1;


    std::string remoteCommand =
        "command -v " +
        shellQuote(command) +
        " >/dev/null 2>&1";


    executeRemote(
        remoteCommand,
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


bool SSHHardening::checkRootOrSudo()
{
    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "id -u",
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Cannot determine remote user.\n";

        return false;
    }


    output.erase(
        std::remove_if(
            output.begin(),
            output.end(),
            [](unsigned char c)
            {
                return std::isspace(c);
            }
        ),
        output.end()
    );


    if (output == "0")
    {
        sudoRequired = false;

        sudoAuthenticated = true;

        return true;
    }


    if (!commandExists("sudo"))
    {
        std::cout
            << "sudo is not installed.\n";

        return false;
    }


    sudoRequired = true;


    if (!authenticateSudo())
    {
        std::cout
            << "Current user cannot use sudo.\n";

        return false;
    }


    return true;
}


bool SSHHardening::checkScript()
{
    std::string output;

    int exitCode = -1;


    std::string command =
        "test -f " +
        shellQuote(HARDENING_SCRIPT);


    executeRemote(
        command,
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


bool SSHHardening::setPermissions()
{
    std::string output;

    int exitCode = -1;


    std::string command =
        "chmod 755 " +
        shellQuote(HARDENING_SCRIPT) +
        " && "
        "chown root:root " +
        shellQuote(HARDENING_SCRIPT);


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot configure script permissions.\n";


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


bool SSHHardening::runHardening()
{
    std::cout
        << "\n";

    std::cout
        << "============================================\n";

    std::cout
        << "          APPLYING SSH HARDENING\n";

    std::cout
        << "============================================\n\n";


    std::string output;

    int exitCode = -1;


    std::string authMethod;

    if (keyAuthentication)
    {
        authMethod = "publickey";

        std::cout
            << "Authentication: SSH private key\n";
    }
    else
    {
        authMethod = "password";

        std::cout
            << "Authentication: password\n";
    }


    std::string command =
        "python3 " +
        shellQuote(HARDENING_SCRIPT) +
        " apply --auth-method=" +
        authMethod;


    std::cout
        << "Running SSH hardening pre-flight checks...\n";


    bool result =
        executeRemote(
            command,
            output,
            exitCode,
            true
        );


    if (!output.empty())
    {
        std::cout
            << output
            << "\n";
    }


    if (!result)
    {
        std::cout
            << "\nSSH hardening failed.\n";

        std::cout
            << "Python exit code: "
            << exitCode
            << "\n";

        hardeningEnabled = false;

        return false;
    }


    if (!checkHardening())
    {
        std::cout
            << "\nSSH hardening was not verified.\n";

        hardeningEnabled = false;

        return false;
    }


    hardeningEnabled = true;


    std::cout
        << "\nSSH hardening completed successfully.\n";


    return true;
}


bool SSHHardening::checkHardening()
{
    std::cout
        << "\n";

    std::cout
        << "============================================\n";

    std::cout
        << "          SSH HARDENING STATUS\n";

    std::cout
        << "============================================\n\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "sshd -T 2>/dev/null";


    if (!executeRemote(
        command,
        output,
        exitCode,
        sudoRequired
    ))
    {
        std::cout
            << "Cannot read effective SSH configuration.\n";

        hardeningEnabled = false;

        return false;
    }


    auto getValue =
        [&](const std::string& name)
        {
            std::istringstream stream(output);

            std::string line;


            while (std::getline(stream, line))
            {
                std::istringstream lineStream(line);

                std::string key;
                std::string value;


                lineStream
                    >> key
                    >> value;


                std::transform(
                    key.begin(),
                    key.end(),
                    key.begin(),
                    [](unsigned char c)
                    {
                        return static_cast<char>(
                            std::tolower(c)
                            );
                    }
                );


                if (key == name)
                {
                    return value;
                }
            }


            return std::string("unknown");
        };


    std::string permitRootLogin =
        getValue("permitrootlogin");

    std::string passwordAuthentication =
        getValue("passwordauthentication");

    std::string pubkeyAuthentication =
        getValue("pubkeyauthentication");

    std::string permitEmptyPasswords =
        getValue("permitemptypasswords");

    std::string maxAuthTries =
        getValue("maxauthtries");

    std::string loginGraceTime =
        getValue("logingracetime");

    std::string x11Forwarding =
        getValue("x11forwarding");

    std::string allowTcpForwarding =
        getValue("allowtcpforwarding");

    std::string allowAgentForwarding =
        getValue("allowagentforwarding");

    std::string compression =
        getValue("compression");


    std::cout
        << "PermitRootLogin: "
        << permitRootLogin
        << "\n";

    std::cout
        << "PasswordAuthentication: "
        << passwordAuthentication
        << "\n";

    std::cout
        << "PubkeyAuthentication: "
        << pubkeyAuthentication
        << "\n";

    std::cout
        << "PermitEmptyPasswords: "
        << permitEmptyPasswords
        << "\n";

    std::cout
        << "MaxAuthTries: "
        << maxAuthTries
        << "\n";

    std::cout
        << "LoginGraceTime: "
        << loginGraceTime
        << "\n";

    std::cout
        << "X11Forwarding: "
        << x11Forwarding
        << "\n";

    std::cout
        << "AllowTcpForwarding: "
        << allowTcpForwarding
        << "\n";

    std::cout
        << "AllowAgentForwarding: "
        << allowAgentForwarding
        << "\n";

    std::cout
        << "Compression: "
        << compression
        << "\n";


    bool allGood = true;


    auto checkValue =
        [&](const std::string& name,
            const std::string& actual,
            const std::string& expected)
        {
            bool valid = false;


            if (name == "PermitRootLogin")
            {
                valid =
                    actual == "prohibit-password" ||
                    actual == "without-password";
            }
            else
            {
                valid =
                    actual == expected;
            }


            if (valid)
            {
                std::cout
                    << "[OK] "
                    << name
                    << " = "
                    << actual
                    << "\n";

                return true;
            }


            std::cout
                << "[FAIL] "
                << name
                << " = "
                << actual
                << " (expected "
                << expected
                << ")\n";


            return false;
        };


    std::cout
        << "\nVerification:\n";





    if (!checkValue(
        "PermitEmptyPasswords",
        permitEmptyPasswords,
        "no"
    ))
    {
        allGood = false;
    }


    if (!checkValue(
        "MaxAuthTries",
        maxAuthTries,
        "3"
    ))
    {
        allGood = false;
    }


    if (!checkValue(
        "LoginGraceTime",
        loginGraceTime,
        "30"
    ))
    {
        allGood = false;
    }


    if (!checkValue(
        "X11Forwarding",
        x11Forwarding,
        "no"
    ))
    {
        allGood = false;
    }



    if (!checkValue(
        "AllowAgentForwarding",
        allowAgentForwarding,
        "no"
    ))
    {
        allGood = false;
    }


    if (!checkValue(
        "Compression",
        compression,
        "no"
    ))
    {
        allGood = false;
    }


    if (checkSSHService())
    {
        std::cout
            << "\nSSH service: ACTIVE\n";
    }
    else
    {
        std::cout
            << "\nSSH service: NOT ACTIVE\n";

        allGood = false;
    }


    if (allGood)
    {
        std::cout
            << "\n============================================\n";

        std::cout
            << "ServerGuard hardening: ENABLED\n";

        std::cout
            << "============================================\n";

        hardeningEnabled = true;
    }
    else
    {
        std::cout
            << "\n============================================\n";

        std::cout
            << "ServerGuard hardening: NOT ENABLED\n";

        std::cout
            << "============================================\n";

        hardeningEnabled = false;
    }


    return allGood;
}


bool SSHHardening::checkSSHService()
{
    std::string output;

    int exitCode = -1;


    executeRemote(
        "systemctl is-active --quiet ssh",
        output,
        exitCode,
        false
    );


    if (exitCode == 0)
    {
        return true;
    }


    executeRemote(
        "systemctl is-active --quiet sshd",
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


bool SSHHardening::isSSHConfigValid()
{
    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "sshd -t",
        output,
        exitCode,
        true
    ))
    {
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


bool SSHHardening::showBackups()
{
    std::string output;

    int exitCode = -1;


    std::string command =
        "ls -lah " +
        shellQuote(BACKUP_DIR) +
        " 2>/dev/null";


    if (!executeRemote(
        command,
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Cannot read backup directory.\n";

        return false;
    }


    std::cout
        << "\n";

    std::cout
        << "============================================\n";

    std::cout
        << "             SSH BACKUPS\n";

    std::cout
        << "============================================\n\n";


    if (output.empty())
    {
        std::cout
            << "No backups found.\n";
    }
    else
    {
        std::cout
            << output
            << "\n";
    }


    return true;
}

bool SSHHardening::restoreConfiguration()
{
    std::cout << "\n";

    showBackups();

    std::cout << "\nEnter backup filename (empty to cancel): ";

    std::string filename;

    std::getline(std::cin >> std::ws, filename);

    // убираем пробелы по краям
    while (!filename.empty() && std::isspace(static_cast<unsigned char>(filename.back())))
        filename.pop_back();

    if (filename.empty())
    {
        return false;
    }

    if (
        filename.find('/') != std::string::npos ||
        filename.find('\\') != std::string::npos ||
        filename.find("..") != std::string::npos
        )
    {
        std::cout << "Invalid backup filename.\n";

        return false;
    }

    const std::string prefix = "pre-hardening_";
    const std::string suffix = ".tar.gz";

    if (
        filename.size() <= prefix.size() + suffix.size() ||
        filename.compare(0, prefix.size(), prefix) != 0 ||
        filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) != 0
        )
    {
        std::cout
            << "Unsupported backup type. Expected: "
            << "pre-hardening_*.tar.gz\n";

        return false;
    }

    if (!checkRootOrSudo())
    {
        return false;
    }

    if (!checkScript())
    {
        std::cout
            << "SSH Hardening script was not found:\n"
            << HARDENING_SCRIPT
            << "\n";

        return false;
    }

    std::string backupPath =
        BACKUP_DIR +
        "/" +
        filename;

    std::string output;

    int exitCode = -1;

    // /opt/serverguard/backups доступна только root, поэтому через sudo
    if (!executeRemote(
        "test -f " + shellQuote(backupPath) +
        " && test -f " + shellQuote(backupPath + ".json"),
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Backup file (or its .json manifest) not found.\n";

        return false;
    }

    std::cout << "\nRestoring configuration...\n";

    std::string command =
        "python3 " +
        shellQuote(HARDENING_SCRIPT) +
        " restore " +
        shellQuote(filename);

    output.clear();

    exitCode = -1;

    bool ok = executeRemote(
        command,
        output,
        exitCode,
        true
    );

    if (!output.empty())
    {
        std::cout
            << "\n"
            << output
            << "\n";
    }

    if (!ok)
    {
        std::cout
            << "\nCannot restore configuration.\n"
            << "Python exit code: "
            << exitCode
            << "\n";

        return false;
    }

    std::cout
        << "\nSSH configuration restored successfully.\n";

    checkHardening();

    return true;
}


bool SSHHardening::downloadUpdate()
{
    std::cout
        << "\n[1/6] Downloading new SSH Hardening script...\n";


    std::string output;

    int exitCode = -1;


    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );


    std::string command =
        "curl -fL "
        "--connect-timeout 15 "
        "--max-time 120 "
        "--retry 2 "
        "-o " +
        shellQuote(HARDENING_TEMP_SCRIPT) +
        " " +
        shellQuote(HARDENING_UPDATE_URL);


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Download failed.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        executeRemote(
            "rm -f " +
            shellQuote(HARDENING_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );


        return false;
    }


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        "test -s " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Downloaded file is empty.\n";


        executeRemote(
            "rm -f " +
            shellQuote(HARDENING_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );


        return false;
    }


    std::cout
        << "Download completed.\n";


    return true;
}


bool SSHHardening::verifyUpdate()
{
    std::cout
        << "[2/6] Checking Python syntax...\n";


    std::string pythonCommand =
        "import ast,sys;"
        "p=open(sys.argv[1],encoding='utf-8').read();"
        "ast.parse(p,filename=sys.argv[1]);"
        "print('Python syntax: OK')";


    std::string command =
        "python3 -c " +
        shellQuote(pythonCommand) +
        " " +
        shellQuote(HARDENING_TEMP_SCRIPT);


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        command,
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Python syntax verification FAILED.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << output;


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        "test -s " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Downloaded script is invalid.\n";

        return false;
    }


    std::cout
        << "Checking current SSH configuration...\n";


    if (!isSSHConfigValid())
    {
        std::cout
            << "Current SSH configuration is invalid.\n"
            << "Update cancelled.\n";

        return false;
    }


    std::cout
        << "Update verification completed.\n";


    return true;
}


bool SSHHardening::backupCurrentScript()
{
    std::cout
        << "[3/6] Creating backup of current SSH Hardening script...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "test -f " +
        shellQuote(HARDENING_SCRIPT),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Current SSH Hardening script not found.\n";

        return false;
    }


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        "mkdir -p " +
        shellQuote(HARDENING_BACKUP_DIR),
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create backup directory.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::string command =
        "cp -p " +
        shellQuote(HARDENING_SCRIPT) +
        " " +
        shellQuote(HARDENING_BACKUP_SCRIPT);


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create backup.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    command =
        "chown root:root " +
        shellQuote(HARDENING_BACKUP_SCRIPT) +
        " && chmod 755 " +
        shellQuote(HARDENING_BACKUP_SCRIPT);


    executeRemote(
        command,
        output,
        exitCode,
        true
    );


    std::cout
        << "Backup created:\n"
        << HARDENING_BACKUP_SCRIPT
        << "\n";


    return true;
}


bool SSHHardening::installUpdatedScript()
{
    std::cout
        << "[4/6] Installing new SSH Hardening script...\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "mv -f " +
        shellQuote(HARDENING_TEMP_SCRIPT) +
        " " +
        shellQuote(HARDENING_SCRIPT);


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot replace SSH Hardening script.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    command =
        "chown root:root " +
        shellQuote(HARDENING_SCRIPT) +
        " && chmod 755 " +
        shellQuote(HARDENING_SCRIPT);


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot configure updated script permissions.\n";

        return false;
    }


    return true;
}


bool SSHHardening::rollbackUpdate()
{
    std::cout
        << "\n============================================\n"
        << "       ROLLING BACK SSH HARDENING\n"
        << "============================================\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "test -f " +
        shellQuote(HARDENING_BACKUP_SCRIPT),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Backup file not found.\n";

        return false;
    }


    std::string command =
        "cp -p " +
        shellQuote(HARDENING_BACKUP_SCRIPT) +
        " " +
        shellQuote(HARDENING_SCRIPT);


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot restore previous script.\n";

        return false;
    }


    command =
        "chown root:root " +
        shellQuote(HARDENING_SCRIPT) +
        " && chmod 755 " +
        shellQuote(HARDENING_SCRIPT);


    executeRemote(
        command,
        output,
        exitCode,
        true
    );


    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );


    if (!isSSHConfigValid())
    {
        std::cout
            << "Previous script restored, "
            << "but SSH configuration is still invalid.\n";

        return false;
    }


    std::cout
        << "\nRollback successful.\n"
        << "Previous SSH Hardening script restored.\n";


    return true;
}


bool SSHHardening::update()
{
    std::cout
        << "\n============================================\n"
        << "        UPDATE SSH HARDENING\n"
        << "============================================\n\n";


    if (!checkRootOrSudo())
    {
        return false;
    }


    if (!checkScript())
    {
        std::cout
            << "SSH Hardening script is not installed:\n"
            << HARDENING_SCRIPT
            << "\n";

        return false;
    }


    if (!commandExists("python3"))
    {
        std::cout
            << "python3 is not installed.\n";

        return false;
    }


    if (!commandExists("curl"))
    {
        std::cout
            << "curl is not installed.\n"
            << "Installing curl...\n";


        std::string output;

        int exitCode = -1;


        if (!executeRemote(
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y curl",
            output,
            exitCode,
            true
        ))
        {
            std::cout
                << "Cannot install curl.\n";


            if (!output.empty())
            {
                std::cout
                    << output
                    << "\n";
            }


            return false;
        }
    }


    if (!downloadUpdate())
    {
        return false;
    }


    if (!verifyUpdate())
    {
        std::cout
            << "\nUpdate cancelled.\n"
            << "Current SSH Hardening script was not changed.\n";


        std::string output;

        int exitCode = -1;


        executeRemote(
            "rm -f " +
            shellQuote(HARDENING_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );


        return false;
    }


    if (!backupCurrentScript())
    {
        std::string output;

        int exitCode = -1;


        executeRemote(
            "rm -f " +
            shellQuote(HARDENING_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );


        return false;
    }


    if (!installUpdatedScript())
    {
        std::cout
            << "\nNew SSH Hardening script was not installed.\n";


        std::string output;

        int exitCode = -1;


        executeRemote(
            "rm -f " +
            shellQuote(HARDENING_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );


        return false;
    }


    std::cout
        << "[5/6] Verifying installed SSH Hardening script...\n";


    std::string output;

    int exitCode = -1;


    std::string pythonCommand =
        "import ast;"
        "p=open('/opt/serverguard/ssh_hardening.py',"
        "encoding='utf-8').read();"
        "ast.parse(p,filename='ssh_hardening.py');"
        "print('Installed script: OK')";


    std::string verifyCommand =
        "python3 -c " +
        shellQuote(pythonCommand);


    if (!executeRemote(
        verifyCommand,
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Installed script verification failed.\n";


        rollbackUpdate();

        return false;
    }


    std::cout
        << output;


    std::cout
        << "[6/6] Final SSH configuration validation...\n";


    if (!isSSHConfigValid())
    {
        std::cout
            << "\nSSH configuration validation failed.\n"
            << "Starting automatic rollback...\n";


        if (!rollbackUpdate())
        {
            std::cout
                << "WARNING: rollback also failed.\n"
                << "Check SSH configuration manually.\n";
        }


        return false;
    }


    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );


    std::cout
        << "\n============================================\n"
        << "   SSH HARDENING UPDATE SUCCESSFUL\n"
        << "============================================\n"
        << "Source:\n"
        << HARDENING_UPDATE_URL
        << "\n\n"
        << "Script:\n"
        << HARDENING_SCRIPT
        << "\n\n"
        << "Backup:\n"
        << HARDENING_BACKUP_SCRIPT
        << "\n\n"
        << "SSH configuration: VALID\n"
        << "============================================\n";


    return true;
}


void SSHHardening::menu()
{
    while (true)
    {
        std::cout
            << "\n"
            << "============================================\n"
            << "             SSH HARDENING\n"
            << "============================================\n"
            << "\n"
            << "1. Apply hardening\n"
            << "2. Check hardening status\n"
            << "3. Disable hardening\n"
            << "4. Show SSH configuration\n"
            << "5. Restore backup\n"
            << "6. Install / update hardening script\n"
            << "0. Back\n"
            << "\n"
            << "Select: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "0")
        {
            return;
        }

        if (choice == "1")
        {
            if (!webApply())
            {
                std::cout
                    << "\n"
                    << "SSH hardening was not applied.\n"
                    << "\n";
            }

            continue;
        }

        if (choice == "2")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            checkHardening();

            continue;
        }

        if (choice == "3")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            if (!checkScript())
            {
                std::cout
                    << "\nSSH hardening script was not found:\n"
                    << HARDENING_SCRIPT
                    << "\n\n";

                continue;
            }

            std::cout
                << "\n"
                << "Disabling SSH hardening...\n";

            std::string output;
            int exitCode = -1;

            std::string command =
                "python3 " +
                shellQuote(HARDENING_SCRIPT) +
                " disable";

            if (!executeRemote(
                command,
                output,
                exitCode,
                true))
            {
                std::cout
                    << "\n"
                    << "Cannot execute remote command.\n";

                continue;
            }

            if (!output.empty())
            {
                std::cout
                    << "\n"
                    << output
                    << "\n";
            }

            if (exitCode != 0)
            {
                std::cout
                    << "\n"
                    << "SSH hardening disable failed.\n"
                    << "Python exit code: "
                    << exitCode
                    << "\n";

                continue;
            }

            hardeningEnabled = false;

            std::cout
                << "\n"
                << "SSH hardening disabled successfully.\n";

            continue;
        }

        if (choice == "4")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            std::string output;
            int exitCode = -1;

            std::string command =
                "sshd -T 2>/dev/null";

            if (!executeRemote(
                command,
                output,
                exitCode,
                true))
            {
                std::cout
                    << "\n"
                    << "Cannot read SSH configuration.\n";

                continue;
            }

            if (exitCode != 0)
            {
                std::cout
                    << "\n"
                    << "Failed to read SSH configuration.\n";

                if (!output.empty())
                {
                    std::cout
                        << output
                        << "\n";
                }

                continue;
            }

            std::cout
                << "\n"
                << "============================================\n"
                << "          EFFECTIVE SSH CONFIGURATION\n"
                << "============================================\n"
                << "\n";

            std::istringstream stream(output);
            std::string line;

            while (std::getline(stream, line))
            {
                if (
                    line.rfind("permitrootlogin ", 0) == 0 ||
                    line.rfind("permitemptypasswords ", 0) == 0 ||
                    line.rfind("pubkeyauthentication ", 0) == 0 ||
                    line.rfind("passwordauthentication ", 0) == 0 ||
                    line.rfind("kbdinteractiveauthentication ", 0) == 0 ||
                    line.rfind("maxauthtries ", 0) == 0 ||
                    line.rfind("logingracetime ", 0) == 0 ||
                    line.rfind("x11forwarding ", 0) == 0 ||
                    line.rfind("allowtcpforwarding ", 0) == 0 ||
                    line.rfind("allowagentforwarding ", 0) == 0 ||
                    line.rfind("compression ", 0) == 0
                    )
                {
                    std::cout << line << "\n";
                }
            }

            std::cout << "\n";

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
                << "Restore backup functionality.\n"
                << "\n";

            continue;
        }

        if (choice == "6")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            if (!checkScript())
            {
                std::cout
                    << "\n"
                    << "SSH hardening script was not found:\n"
                    << HARDENING_SCRIPT
                    << "\n\n";

                std::cout
                    << "Use the Web API or the existing "
                    << "installation mechanism to install "
                    << "the script.\n";

                continue;
            }

            std::cout
                << "\n"
                << "SSH hardening script is already installed:\n"
                << HARDENING_SCRIPT
                << "\n";

            continue;
        }

        std::cout
            << "\n"
            << "Invalid option.\n";
    }
}


bool SSHHardening::isEnabled() const
{
    return hardeningEnabled;
}


bool SSHHardening::webInstall()
{
    std::cout
        << "\n============================================\n"
        << "        INSTALL SSH HARDENING\n"
        << "============================================\n\n";


    if (!checkRootOrSudo())
    {
        return false;
    }


    if (!commandExists("python3"))
    {
        std::cout
            << "python3 is not installed.\n";

        return false;
    }


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "mkdir -p " +
        shellQuote(SERVERGUARD_DIR),
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create ServerGuard directory.\n";


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
            << "curl is not installed.\n"
            << "Installing curl...\n";


        output.clear();

        exitCode = -1;


        if (!executeRemote(
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y curl",
            output,
            exitCode,
            true
        ))
        {
            std::cout
                << "Cannot install curl.\n";


            if (!output.empty())
            {
                std::cout
                    << output
                    << "\n";
            }


            return false;
        }
    }


    if (checkScript())
    {
        std::cout
            << "SSH Hardening script is already installed.\n";

        return true;
    }


    if (!downloadUpdate())
    {
        return false;
    }


    std::cout
        << "Verifying downloaded SSH Hardening script...\n";


    if (!verifyUpdate())
    {
        std::cout
            << "Downloaded SSH Hardening script failed verification.\n";


        output.clear();

        exitCode = -1;


        executeRemote(
            "rm -f " +
            shellQuote(HARDENING_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );


        return false;
    }


    if (!installUpdatedScript())
    {
        std::cout
            << "Cannot install SSH Hardening script.\n";


        output.clear();

        exitCode = -1;


        executeRemote(
            "rm -f " +
            shellQuote(HARDENING_TEMP_SCRIPT),
            output,
            exitCode,
            true
        );


        return false;
    }


    if (!checkScript())
    {
        std::cout
            << "SSH Hardening installation verification failed.\n";

        return false;
    }


    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );


    std::cout
        << "\n============================================\n"
        << "   SSH HARDENING INSTALLATION SUCCESSFUL\n"
        << "============================================\n"
        << "Script:\n"
        << HARDENING_SCRIPT
        << "\n\n"
        << "SSH configuration was NOT changed.\n"
        << "Use Apply Hardening to apply the configuration.\n"
        << "============================================\n";


    return true;
}


bool SSHHardening::webRemove()
{
    std::cout
        << "\n============================================\n"
        << "        REMOVE SSH HARDENING\n"
        << "============================================\n\n";


    if (!checkRootOrSudo())
    {
        return false;
    }


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "mkdir -p " +
        shellQuote(HARDENING_BACKUP_DIR),
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create hardening backup directory.\n";

        return false;
    }


    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_CONFIG_BACKUP),
        output,
        exitCode,
        true
    );


    std::string backupCommand =
        "if [ -f " +
        shellQuote(HARDENING_CONFIG) +
        " ]; then "
        "cp -p " +
        shellQuote(HARDENING_CONFIG) +
        " " +
        shellQuote(HARDENING_CONFIG_BACKUP) +
        "; "
        "fi";


    if (!executeRemote(
        backupCommand,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot backup SSH Hardening configuration.\n";

        return false;
    }


    std::cout
        << "Removing ServerGuard SSH configuration...\n";


    std::string removeConfigCommand =
        "rm -f " +
        shellQuote(HARDENING_CONFIG);


    if (!executeRemote(
        removeConfigCommand,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot remove SSH Hardening configuration.\n";

        return false;
    }


    std::cout
        << "Validating SSH configuration...\n";


    if (!isSSHConfigValid())
    {
        std::cout
            << "\nSSH configuration became invalid after removal.\n"
            << "Restoring ServerGuard hardening configuration...\n";


        std::string restoreCommand =
            "if [ -f " +
            shellQuote(HARDENING_CONFIG_BACKUP) +
            " ]; then "
            "cp -p " +
            shellQuote(HARDENING_CONFIG_BACKUP) +
            " " +
            shellQuote(HARDENING_CONFIG) +
            "; "
            "fi";


        executeRemote(
            restoreCommand,
            output,
            exitCode,
            true
        );


        if (isSSHConfigValid())
        {
            std::cout
                << "SSH Hardening configuration restored.\n";
        }
        else
        {
            std::cout
                << "WARNING: SSH configuration could not be "
                << "automatically restored.\n";
        }


        return false;
    }


    std::cout
        << "Removing SSH Hardening script...\n";


    std::string removeScriptCommand =
        "rm -f " +
        shellQuote(HARDENING_SCRIPT) +
        " " +
        shellQuote(HARDENING_TEMP_SCRIPT);


    if (!executeRemote(
        removeScriptCommand,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot remove SSH Hardening script.\n";


        std::string restoreCommand =
            "if [ -f " +
            shellQuote(HARDENING_CONFIG_BACKUP) +
            " ]; then "
            "cp -p " +
            shellQuote(HARDENING_CONFIG_BACKUP) +
            " " +
            shellQuote(HARDENING_CONFIG) +
            "; "
            "fi";


        executeRemote(
            restoreCommand,
            output,
            exitCode,
            true
        );


        return false;
    }


    output.clear();

    exitCode = -1;


    if (executeRemote(
        "test -f " +
        shellQuote(HARDENING_SCRIPT),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "SSH Hardening script still exists.\n";

        return false;
    }


    if (!isSSHConfigValid())
    {
        std::cout
            << "Final SSH configuration validation failed.\n";

        return false;
    }


    std::cout
        << "Reloading SSH service...\n";


    std::string reloadCommand =
        "systemctl reload ssh 2>/dev/null || "
        "systemctl reload sshd 2>/dev/null";


    if (!executeRemote(
        reloadCommand,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "SSH reload failed.\n";

        return false;
    }


    hardeningEnabled = false;


    std::cout
        << "\n============================================\n"
        << "     SSH HARDENING REMOVED SUCCESSFULLY\n"
        << "============================================\n"
        << "Script removed:\n"
        << HARDENING_SCRIPT
        << "\n\n"
        << "ServerGuard configuration removed:\n"
        << HARDENING_CONFIG
        << "\n\n"
        << "Backup:\n"
        << HARDENING_CONFIG_BACKUP
        << "\n\n"
        << "Main SSH configuration was NOT deleted.\n"
        << "SSH configuration: VALID\n"
        << "============================================\n";


    return true;
}

bool SSHHardening::webApply()
{
    if (!keyAuthentication)
    {
        std::cout
            << "\n"
            << "============================================\n"
            << "       SSH HARDENING SAFETY CHECK\n"
            << "============================================\n"
            << "\n"
            << "[FAIL] ServerGuard is connected using password authentication.\n"
            << "[FAIL] SSH hardening was blocked for safety.\n"
            << "[INFO] Password authentication will NOT be disabled.\n"
            << "[INFO] Connect to the server using an SSH private key first.\n"
            << "\n";

        return false;
    }


    if (!checkRootOrSudo())
    {
        return false;
    }


    if (!checkScript())
    {
        std::cout
            << "SSH Hardening script was not found:\n"
            << HARDENING_SCRIPT
            << "\n";

        return false;
    }


    if (!setPermissions())
    {
        return false;
    }


    return runHardening();
}


bool SSHHardening::webValidate()
{
    if (!checkRootOrSudo())
    {
        return false;
    }


    return isSSHConfigValid();
}


bool SSHHardening::webUpdate()
{
    return update();
}


std::string SSHHardening::webStatus()
{
    std::string output;

    int exitCode = -1;


    bool sshActive =
        checkSSHService();


    std::string permitRootLogin = "unknown";
    std::string permitEmptyPasswords = "unknown";
    std::string maxAuthTries = "unknown";
    std::string loginGraceTime = "unknown";
    std::string x11Forwarding = "unknown";
    std::string allowTcpForwarding = "unknown";
    std::string allowAgentForwarding = "unknown";
    std::string compression = "unknown";


    if (sshActive)
    {
        if (executeRemote(
            "sshd -T 2>/dev/null",
            output,
            exitCode,
            sudoRequired
        ))
        {
            auto getValue =
                [&](const std::string& name)
                {
                    std::istringstream stream(output);

                    std::string line;


                    while (std::getline(stream, line))
                    {
                        std::istringstream lineStream(line);

                        std::string key;
                        std::string value;


                        lineStream
                            >> key
                            >> value;


                        std::transform(
                            key.begin(),
                            key.end(),
                            key.begin(),
                            [](unsigned char c)
                            {
                                return static_cast<char>(
                                    std::tolower(c)
                                    );
                            }
                        );


                        if (key == name)
                        {
                            return value;
                        }
                    }


                    return std::string("unknown");
                };


            permitRootLogin =
                getValue("permitrootlogin");

            permitEmptyPasswords =
                getValue("permitemptypasswords");

            maxAuthTries =
                getValue("maxauthtries");

            loginGraceTime =
                getValue("logingracetime");

            x11Forwarding =
                getValue("x11forwarding");

            allowTcpForwarding =
                getValue("allowtcpforwarding");

            allowAgentForwarding =
                getValue("allowagentforwarding");

            compression =
                getValue("compression");
        }
    }


    bool rootProtected =
        permitRootLogin == "prohibit-password" ||
        permitRootLogin == "without-password";


    bool realHardening =
        sshActive &&
        permitEmptyPasswords == "no" &&
        maxAuthTries == "3" &&
        loginGraceTime == "30" &&
        x11Forwarding == "no" &&
        allowAgentForwarding == "no" &&
        compression == "no";


    hardeningEnabled =
        realHardening;


    bool scriptInstalled =
        checkScript();


    bool configValid =
        isSSHConfigValid();


    std::ostringstream json;


    json
        << "{"
        << "\"installed\":"
        << (scriptInstalled ? "true" : "false")

        << ",\"enabled\":"
        << (realHardening ? "true" : "false")

        << ",\"sshActive\":"
        << (sshActive ? "true" : "false")

        << ",\"configValid\":"
        << (configValid ? "true" : "false")

        << ",\"scriptPath\":\""
        << HARDENING_SCRIPT
        << "\""

        << ",\"configPath\":\""
        << SSH_CONFIG
        << "\""

        << ",\"hardeningConfig\":\""
        << HARDENING_CONFIG
        << "\""

        << ",\"permitRootLogin\":\""
        << permitRootLogin
        << "\""

        << ",\"permitEmptyPasswords\":\""
        << permitEmptyPasswords
        << "\""

        << ",\"maxAuthTries\":\""
        << maxAuthTries
        << "\""

        << ",\"loginGraceTime\":\""
        << loginGraceTime
        << "\""

        << ",\"x11Forwarding\":\""
        << x11Forwarding
        << "\""

        << ",\"allowTcpForwarding\":\""
        << allowTcpForwarding
        << "\""

        << ",\"allowAgentForwarding\":\""
        << allowAgentForwarding
        << "\""

        << ",\"compression\":\""
        << compression
        << "\""

        << "}";


    return json.str();
}


std::string SSHHardening::webBackups()
{
    std::string output;

    int exitCode = -1;


    std::string command =
        "ls -lah " +
        shellQuote(BACKUP_DIR) +
        " 2>/dev/null";


    executeRemote(
        command,
        output,
        exitCode,
        false
    );


    std::ostringstream json;


    json
        << "{"
        << "\"ok\":"
        << (exitCode == 0 ? "true" : "false")
        << ",\"path\":\""
        << BACKUP_DIR
        << "\""
        << ",\"text\":\"";


    for (char c : output)
    {
        switch (c)
        {
        case '\\':
            json << "\\\\";
            break;

        case '"':
            json << "\\\"";
            break;

        case '\n':
            json << "\\n";
            break;

        case '\r':
            json << "\\r";
            break;

        case '\t':
            json << "\\t";
            break;

        default:
            json << c;
            break;
        }
    }


    json
        << "\""
        << "}";


    return json.str();
}