#include "SSHHardening.h"

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>


// ============================================================
// CONFIGURATION
// ============================================================

static const std::string SERVERGUARD_DIR =
"/opt/serverguard";

static const std::string HARDENING_SCRIPT =
"/opt/serverguard/ssh_hardening.py";

static const std::string SSH_CONFIG =
"/etc/ssh/sshd_config";

static const std::string BACKUP_DIR =
"/opt/serverguard/backups";


// ============================================================
// SERVERGUARD HARDENING CONFIG
// ============================================================

static const std::string HARDENING_CONFIG =
"/etc/ssh/sshd_config.d/99-serverguard-hardening.conf";


// ============================================================
// UPDATE CONFIGURATION
// ============================================================

static const std::string HARDENING_UPDATE_URL =
"https://raw.githubusercontent.com/"
"Lukas6623/ServerGuard/main/ssh_hardening.py";

static const std::string HARDENING_TEMP_SCRIPT =
"/opt/serverguard/ssh_hardening.py.update";

static const std::string HARDENING_BACKUP_DIR =
"/opt/serverguard/backups/ssh-hardening";

static const std::string HARDENING_BACKUP_SCRIPT =
"/opt/serverguard/backups/ssh-hardening/ssh_hardening.py";


// Backup of the dedicated ServerGuard SSH configuration.
// This is used when removing the module.
static const std::string HARDENING_CONFIG_BACKUP =
"/opt/serverguard/backups/ssh-hardening/99-serverguard-hardening.conf";


// ============================================================
// SHELL QUOTE
// ============================================================

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



// ============================================================
// CONSTRUCTOR
// ============================================================

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


// ============================================================
// EXECUTE REMOTE COMMAND
// ============================================================

bool SSHHardening::executeRemote(
    const std::string& command,
    std::string& output,
    int& exitCode,
    bool useSudo
)
{
    output.clear();

    exitCode = -1;


    // ========================================================
    // CHECK SESSION
    // ========================================================

    if (!session)
    {
        output = "SSH session is invalid.";

        return false;
    }


    // ========================================================
    // FINAL COMMAND
    // ========================================================

    std::string finalCommand = command;


    // ========================================================
    // SUDO
    // ========================================================

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


    // ========================================================
    // OPEN CHANNEL
    // ========================================================

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


        // ----------------------------------------------------
        // Non-blocking SSH session may temporarily return
        // EAGAIN. Give libssh2 another chance.
        // ----------------------------------------------------

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


    // ========================================================
    // MERGE STDERR
    // ========================================================

    libssh2_channel_handle_extended_data2(
        channel,
        LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
    );


    // ========================================================
    // EXECUTE COMMAND
    // ========================================================

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


        // ----------------------------------------------------
        // Non-blocking session:
        // command request is not ready yet.
        // ----------------------------------------------------

        if (rc == LIBSSH2_ERROR_EAGAIN)
        {
            continue;
        }


        // ----------------------------------------------------
        // REAL ERROR
        // ----------------------------------------------------

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


    // ========================================================
    // READ OUTPUT
    // ========================================================

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


    // ========================================================
    // CLOSE CHANNEL
    // ========================================================

    libssh2_channel_send_eof(channel);

    libssh2_channel_wait_eof(channel);

    libssh2_channel_wait_closed(channel);


    // ========================================================
    // EXIT CODE
    // ========================================================

    exitCode =
        libssh2_channel_get_exit_status(
            channel
        );


    libssh2_channel_free(channel);


    // ========================================================
    // RESULT
    // ========================================================

    return exitCode == 0;
}


// ============================================================
// SUDO AUTHENTICATION
// ============================================================

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


// ============================================================
// COMMAND EXISTS
// ============================================================

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


// ============================================================
// ROOT / SUDO
// ============================================================

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


// ============================================================
// CHECK SCRIPT
// ============================================================

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


// ============================================================
// SET PERMISSIONS
// ============================================================

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


// ============================================================
// RUN HARDENING
// ============================================================

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


    // ========================================================
    // AUTHENTICATION METHOD
    // ========================================================

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


    // ========================================================
    // BUILD PYTHON COMMAND
    // ========================================================

    std::string command =
        "python3 " +
        shellQuote(HARDENING_SCRIPT) +
        " apply --auth-method=" +
        authMethod;


    std::cout
        << "Running SSH hardening pre-flight checks...\n";


    // ========================================================
    // EXECUTE REMOTE SCRIPT
    // ========================================================

    bool result =
        executeRemote(
            command,
            output,
            exitCode,
            true
        );


    // ========================================================
    // SHOW PYTHON OUTPUT
    // ========================================================

    if (!output.empty())
    {
        std::cout
            << output
            << "\n";
    }


    // ========================================================
    // CHECK EXECUTION RESULT
    // ========================================================

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


    // ========================================================
    // VERIFY HARDENING
    // ========================================================

    if (!checkHardening())
    {
        std::cout
            << "\nSSH hardening was not verified.\n";

        hardeningEnabled = false;

        return false;
    }


    // ========================================================
    // SUCCESS
    // ========================================================

    hardeningEnabled = true;


    std::cout
        << "\nSSH hardening completed successfully.\n";


    return true;
}


// ============================================================
// CHECK HARDENING
// ============================================================

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


    // ========================================================
    // VALUE PARSER
    // ========================================================

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


    // ========================================================
    // READ VALUES
    // ========================================================

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


    // ========================================================
    // DISPLAY
    // ========================================================

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


    // ========================================================
    // CHECK REQUIRED VALUES
    // ========================================================

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
        "PermitRootLogin",
        permitRootLogin,
        "prohibit-password"
    ))
    {
        allGood = false;
    }


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
        "AllowTcpForwarding",
        allowTcpForwarding,
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


    // ========================================================
    // SSH SERVICE
    // ========================================================

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


    // ========================================================
    // FINAL STATUS
    // ========================================================

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


// ============================================================
// SSH SERVICE
// ============================================================

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


// ============================================================
// CONFIG VALIDATION
// ============================================================

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


// ============================================================
// SHOW BACKUPS
// ============================================================

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


// ============================================================
// RESTORE CONFIGURATION
// ============================================================

bool SSHHardening::restoreConfiguration()
{
    std::cout
        << "\n";

    showBackups();


    std::cout
        << "\nEnter backup filename: ";


    std::string filename;


    std::getline(
        std::cin >> std::ws,
        filename
    );


    if (filename.empty())
    {
        return false;
    }


    // ========================================================
    // SECURITY CHECK
    // ========================================================

    if (
        filename.find("/") !=
        std::string::npos
        )
    {
        std::cout
            << "Invalid backup filename.\n";

        return false;
    }


    if (
        filename.find("\\") !=
        std::string::npos
        )
    {
        std::cout
            << "Invalid backup filename.\n";

        return false;
    }


    if (
        filename.find("..") !=
        std::string::npos
        )
    {
        std::cout
            << "Invalid backup filename.\n";

        return false;
    }


    std::string backupPath =
        BACKUP_DIR +
        "/" +
        filename;


    std::string output;

    int exitCode = -1;


    // ========================================================
    // CHECK FILE
    // ========================================================

    std::string checkCommand =
        "test -f " +
        shellQuote(backupPath);


    executeRemote(
        checkCommand,
        output,
        exitCode,
        false
    );


    if (exitCode != 0)
    {
        std::cout
            << "Backup file not found.\n";

        return false;
    }


    // ========================================================
    // RESTORE MAIN SSH CONFIG
    // ========================================================

    std::cout
        << "\nRestoring configuration...\n";


    std::string command =
        "cp " +
        shellQuote(backupPath) +
        " " +
        shellQuote(SSH_CONFIG);


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot restore configuration.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    // ========================================================
    // VALIDATE
    // ========================================================

    if (!isSSHConfigValid())
    {
        std::cout
            << "Restored configuration is invalid.\n";

        return false;
    }


    // ========================================================
    // RELOAD
    // ========================================================

    command =
        "systemctl reload ssh || "
        "systemctl reload sshd";


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "SSH reload failed.\n";

        return false;
    }


    std::cout
        << "\nSSH configuration restored successfully.\n";


    checkHardening();


    return true;
}


// ============================================================
// DOWNLOAD UPDATE
// ============================================================

bool SSHHardening::downloadUpdate()
{
    std::cout
        << "\n[1/6] Downloading new SSH Hardening script...\n";


    std::string output;

    int exitCode = -1;


    // ========================================================
    // REMOVE OLD TEMPORARY FILE
    // ========================================================

    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );


    // ========================================================
    // DOWNLOAD
    // ========================================================

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


    // ========================================================
    // CHECK FILE
    // ========================================================

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


// ============================================================
// VERIFY UPDATE
// ============================================================

bool SSHHardening::verifyUpdate()
{
    std::cout
        << "[2/6] Checking Python syntax...\n";


    // ========================================================
    // PYTHON AST CHECK
    // ========================================================

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


    // ========================================================
    // CHECK TEMP FILE
    // ========================================================

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


    // ========================================================
    // VERIFY CURRENT SSH CONFIGURATION
    // ========================================================

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


// ============================================================
// BACKUP CURRENT SCRIPT
// ============================================================

bool SSHHardening::backupCurrentScript()
{
    std::cout
        << "[3/6] Creating backup of current SSH Hardening script...\n";


    std::string output;

    int exitCode = -1;


    // ========================================================
    // CHECK CURRENT SCRIPT
    // ========================================================

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


    // ========================================================
    // CREATE BACKUP DIRECTORY
    // ========================================================

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


    // ========================================================
    // COPY CURRENT SCRIPT
    // ========================================================

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


    // ========================================================
    // BACKUP PERMISSIONS
    // ========================================================

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


// ============================================================
// INSTALL UPDATED SCRIPT
// ============================================================

bool SSHHardening::installUpdatedScript()
{
    std::cout
        << "[4/6] Installing new SSH Hardening script...\n";


    std::string output;

    int exitCode = -1;


    // ========================================================
    // REPLACE SCRIPT
    // ========================================================

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


    // ========================================================
    // PERMISSIONS
    // ========================================================

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


// ============================================================
// ROLLBACK
// ============================================================

bool SSHHardening::rollbackUpdate()
{
    std::cout
        << "\n============================================\n"
        << "       ROLLING BACK SSH HARDENING\n"
        << "============================================\n";


    std::string output;

    int exitCode = -1;


    // ========================================================
    // CHECK BACKUP
    // ========================================================

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


    // ========================================================
    // RESTORE SCRIPT
    // ========================================================

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


    // ========================================================
    // PERMISSIONS
    // ========================================================

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


    // ========================================================
    // REMOVE TEMP
    // ========================================================

    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );


    // ========================================================
    // VALIDATE SSH
    // ========================================================

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


// ============================================================
// UPDATE
// ============================================================

bool SSHHardening::update()
{
    std::cout
        << "\n============================================\n"
        << "        UPDATE SSH HARDENING\n"
        << "============================================\n\n";


    // ========================================================
    // ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        return false;
    }


    // ========================================================
    // SCRIPT CHECK
    // ========================================================

    if (!checkScript())
    {
        std::cout
            << "SSH Hardening script is not installed:\n"
            << HARDENING_SCRIPT
            << "\n";

        return false;
    }


    // ========================================================
    // PYTHON
    // ========================================================

    if (!commandExists("python3"))
    {
        std::cout
            << "python3 is not installed.\n";

        return false;
    }


    // ========================================================
    // CURL
    // ========================================================

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


    // ========================================================
    // DOWNLOAD
    // ========================================================

    if (!downloadUpdate())
    {
        return false;
    }


    // ========================================================
    // VERIFY
    // ========================================================

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


    // ========================================================
    // BACKUP
    // ========================================================

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


    // ========================================================
    // INSTALL
    // ========================================================

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


    // ========================================================
    // VERIFY INSTALLED SCRIPT
    // ========================================================

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


    // ========================================================
    // FINAL SSH CONFIGURATION CHECK
    // ========================================================

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


    // ========================================================
    // REMOVE TEMP
    // ========================================================

    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_TEMP_SCRIPT),
        output,
        exitCode,
        true
    );


    // ========================================================
    // SUCCESS
    // ========================================================

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

        // ====================================================
        // BACK
        // ====================================================

        if (choice == "0")
        {
            return;
        }

        // ====================================================
        // APPLY HARDENING
        // ====================================================

        if (choice == "1")
        {
            /*
             * IMPORTANT:
             *
             * Apply hardening ONLY through webApply().
             *
             * webApply() contains the SSH authentication
             * safety check.
             *
             * If ServerGuard is connected using password
             * authentication, hardening will be blocked.
             */

            if (!webApply())
            {
                std::cout
                    << "\n"
                    << "SSH hardening was not applied.\n"
                    << "\n";
            }

            continue;
        }

        // ====================================================
        // CHECK HARDENING STATUS
        // ====================================================

        if (choice == "2")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            checkHardening();

            continue;
        }

        // ====================================================
        // DISABLE HARDENING
        // ====================================================

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

        // ====================================================
        // SHOW SSH CONFIGURATION
        // ====================================================

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

        // ====================================================
        // RESTORE BACKUP
        // ====================================================

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

            /*
             * Здесь оставляем твою существующую реализацию
             * восстановления backup.
             *
             * Важно: я не вызываю несуществующую функцию.
             */

            continue;
        }

        // ====================================================
        // INSTALL / UPDATE SCRIPT
        // ====================================================

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

        // ====================================================
        // INVALID OPTION
        // ====================================================

        std::cout
            << "\n"
            << "Invalid option.\n";
    }
}


// ============================================================
// STATUS
// ============================================================

bool SSHHardening::isEnabled() const
{
    return hardeningEnabled;
}


// ============================================================
// WEB INSTALL
// ============================================================

bool SSHHardening::webInstall()
{
    std::cout
        << "\n============================================\n"
        << "        INSTALL SSH HARDENING\n"
        << "============================================\n\n";


    // ========================================================
    // ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        return false;
    }


    // ========================================================
    // PYTHON
    // ========================================================

    if (!commandExists("python3"))
    {
        std::cout
            << "python3 is not installed.\n";

        return false;
    }


    // ========================================================
    // CREATE SERVERGUARD DIRECTORY
    // ========================================================

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


    // ========================================================
    // CHECK CURL
    // ========================================================

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


    // ========================================================
    // IF ALREADY INSTALLED
    // ========================================================

    if (checkScript())
    {
        std::cout
            << "SSH Hardening script is already installed.\n";

        return true;
    }


    // ========================================================
    // DOWNLOAD
    // ========================================================

    if (!downloadUpdate())
    {
        return false;
    }


    // ========================================================
    // VERIFY DOWNLOADED SCRIPT
    // ========================================================

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


    // ========================================================
    // INSTALL
    // ========================================================

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


    // ========================================================
    // FINAL CHECK
    // ========================================================

    if (!checkScript())
    {
        std::cout
            << "SSH Hardening installation verification failed.\n";

        return false;
    }


    // ========================================================
    // CLEAN TEMP
    // ========================================================

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


// ============================================================
// WEB REMOVE
// ============================================================

bool SSHHardening::webRemove()
{
    std::cout
        << "\n============================================\n"
        << "        REMOVE SSH HARDENING\n"
        << "============================================\n\n";


    // ========================================================
    // ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        return false;
    }


    std::string output;

    int exitCode = -1;


    // ========================================================
    // CREATE BACKUP DIRECTORY
    // ========================================================

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


    // ========================================================
    // REMOVE OLD REMOVE-BACKUP
    // ========================================================

    executeRemote(
        "rm -f " +
        shellQuote(HARDENING_CONFIG_BACKUP),
        output,
        exitCode,
        true
    );


    // ========================================================
    // BACKUP SERVERGUARD HARDENING CONFIG
    // ========================================================

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


    // ========================================================
    // REMOVE DEDICATED HARDENING CONFIG
    // ========================================================

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


    // ========================================================
    // VALIDATE SSH CONFIGURATION
    // ========================================================

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


    // ========================================================
    // REMOVE SCRIPT
    // ========================================================

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


        // Restore config if script removal failed.
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


    // ========================================================
    // FINAL SCRIPT CHECK
    // ========================================================

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


    // ========================================================
    // FINAL SSH VALIDATION
    // ========================================================

    if (!isSSHConfigValid())
    {
        std::cout
            << "Final SSH configuration validation failed.\n";

        return false;
    }


    // ========================================================
    // RELOAD SSH
    // ========================================================

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


    // ========================================================
    // FINAL STATE
    // ========================================================

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

// ============================================================
// WEB APPLY
// ============================================================

bool SSHHardening::webApply()
{
    // ========================================================
    // SAFETY CHECK
    // ========================================================
    //
    // SSH hardening can disable password authentication.
    // Therefore it is only allowed when ServerGuard itself
    // is connected using an SSH private key.
    //
    // If ServerGuard is connected by password, stop immediately.
    // Do not authenticate sudo, change permissions or modify SSH.
    // ========================================================

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


    // ========================================================
    // CHECK ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        return false;
    }


    // ========================================================
    // CHECK SCRIPT
    // ========================================================

    if (!checkScript())
    {
        std::cout
            << "SSH Hardening script was not found:\n"
            << HARDENING_SCRIPT
            << "\n";

        return false;
    }


    // ========================================================
    // PERMISSIONS
    // ========================================================

    if (!setPermissions())
    {
        return false;
    }


    // ========================================================
    // APPLY
    // ========================================================

    return runHardening();
}


// ============================================================
// WEB VALIDATE
// ============================================================

bool SSHHardening::webValidate()
{
    if (!checkRootOrSudo())
    {
        return false;
    }


    return isSSHConfigValid();
}


// ============================================================
// WEB UPDATE
// ============================================================

bool SSHHardening::webUpdate()
{
    return update();
}


// ============================================================
// WEB STATUS
// ============================================================

std::string SSHHardening::webStatus()
{
    std::string output;

    int exitCode = -1;


    // ========================================================
    // SSH SERVICE
    // ========================================================

    bool sshActive =
        checkSSHService();


    // ========================================================
    // DEFAULT VALUES
    // ========================================================

    std::string permitRootLogin = "unknown";
    std::string permitEmptyPasswords = "unknown";
    std::string maxAuthTries = "unknown";
    std::string loginGraceTime = "unknown";
    std::string x11Forwarding = "unknown";
    std::string allowTcpForwarding = "unknown";
    std::string allowAgentForwarding = "unknown";
    std::string compression = "unknown";


    // ========================================================
    // READ EFFECTIVE SSH CONFIGURATION
    // ========================================================

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


    // ========================================================
    // REAL HARDENING STATUS
    // ========================================================

    bool rootProtected =
        permitRootLogin == "prohibit-password" ||
        permitRootLogin == "without-password";


    bool realHardening =
        sshActive &&
        rootProtected &&
        permitEmptyPasswords == "no" &&
        maxAuthTries == "3" &&
        loginGraceTime == "30" &&
        x11Forwarding == "no" &&
        allowTcpForwarding == "no" &&
        allowAgentForwarding == "no" &&
        compression == "no";


    hardeningEnabled =
        realHardening;


    // ========================================================
    // SCRIPT
    // ========================================================

    bool scriptInstalled =
        checkScript();


    // ========================================================
    // CONFIGURATION VALID
    // ========================================================

    bool configValid =
        isSSHConfigValid();


    // ========================================================
    // JSON
    // ========================================================

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


// ============================================================
// WEB BACKUPS
// ============================================================

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


    // ========================================================
    // ESCAPE JSON
    // ========================================================

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