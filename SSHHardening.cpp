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
    const std::string& password
)
{
    session = sshSession;

    sudoPassword = password;

    sudoRequired = false;

    sudoAuthenticated = false;

    hardeningEnabled = false;
}


// ============================================================
// EXECUTE REMOTE
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

    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(
            session
        );

    if (!channel)
    {
        output = "Cannot open SSH channel.";

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
    // EXECUTE
    // ========================================================

    if (libssh2_channel_exec(
        channel,
        finalCommand.c_str()
    ) != 0)
    {
        output = "Cannot execute remote command.";

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

        std::cout
            << "Remote user is root.\n";

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


    std::string command =
        "python3 " +
        shellQuote(HARDENING_SCRIPT) +
        " apply";


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


    std::cout
        << "SSH configuration is VALID.\n";


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


    // ========================================================
    // REMOVE OLD TEMPORARY FILE
    // ========================================================

    std::string output;

    int exitCode = -1;


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


// ============================================================
// MENU
// ============================================================

void SSHHardening::menu()
{
    while (true)
    {
        std::cout
            << "\n";

        std::cout
            << "============================================\n";

        std::cout
            << "           SSH HARDENING MENU\n";

        std::cout
            << "============================================\n\n";


        // ====================================================
        // REFRESH STATUS
        // ====================================================

        bool sshActive =
            checkSSHService();


        std::cout
            << "SSH service: "
            << (
                sshActive
                ? "ACTIVE"
                : "INACTIVE"
                )
            << "\n";


        // ====================================================
        // REAL HARDENING STATUS
        // ====================================================

        bool realHardening = false;


        if (sshActive)
        {
            std::string output;

            int exitCode = -1;


            if (executeRemote(
                "sshd -T 2>/dev/null",
                output,
                exitCode,
                sudoRequired
            ))
            {
                auto getMenuValue =
                    [&](const std::string& name)
                    {
                        std::istringstream stream(output);

                        std::string line;


                        while (std::getline(
                            stream,
                            line
                        ))
                        {
                            std::istringstream ls(line);

                            std::string key;
                            std::string value;


                            ls
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


                std::string menuPermitRootLogin =
                    getMenuValue(
                        "permitrootlogin"
                    );


                bool rootLoginProtected =
                    menuPermitRootLogin ==
                    "prohibit-password"
                    ||
                    menuPermitRootLogin ==
                    "without-password";


                realHardening =
                    rootLoginProtected
                    &&
                    getMenuValue(
                        "permitemptypasswords"
                    ) == "no"
                    &&
                    getMenuValue(
                        "maxauthtries"
                    ) == "3"
                    &&
                    getMenuValue(
                        "logingracetime"
                    ) == "30"
                    &&
                    getMenuValue(
                        "x11forwarding"
                    ) == "no"
                    &&
                    getMenuValue(
                        "allowtcpforwarding"
                    ) == "no"
                    &&
                    getMenuValue(
                        "allowagentforwarding"
                    ) == "no"
                    &&
                    getMenuValue(
                        "compression"
                    ) == "no";
            }
        }


        hardeningEnabled =
            realHardening;


        if (hardeningEnabled)
        {
            std::cout
                << "ServerGuard hardening: ENABLED\n";
        }
        else
        {
            std::cout
                << "ServerGuard hardening: NOT ENABLED\n";
        }


        std::cout
            << "\n";


        // ====================================================
        // OPTIONS
        // ====================================================

        std::cout
            << "1. Apply SSH hardening\n";

        std::cout
            << "2. Check current SSH configuration\n";

        std::cout
            << "3. Validate SSH configuration\n";

        std::cout
            << "4. Show configuration backups\n";

        std::cout
            << "5. Restore configuration\n";

        std::cout
            << "6. Update SSH Hardening\n";

        std::cout
            << "0. Back\n\n";


        std::cout
            << "Select: ";


        std::string choice;


        std::getline(
            std::cin >> std::ws,
            choice
        );


        // ====================================================
        // APPLY
        // ====================================================

        if (choice == "1")
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


                std::cout
                    << "Place the script on the server manually "
                    << "before applying SSH hardening.\n";


                continue;
            }


            std::cout
                << "\nSSH hardening script found.\n";


            if (!setPermissions())
            {
                continue;
            }


            runHardening();

            continue;
        }


        // ====================================================
        // CHECK
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
        // VALIDATE
        // ====================================================

        if (choice == "3")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }


            if (isSSHConfigValid())
            {
                std::cout
                    << "SSH configuration is VALID.\n";
            }
            else
            {
                std::cout
                    << "SSH configuration is INVALID.\n";
            }


            continue;
        }


        // ====================================================
        // BACKUPS
        // ====================================================

        if (choice == "4")
        {
            showBackups();

            continue;
        }


        // ====================================================
        // RESTORE
        // ====================================================

        if (choice == "5")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }


            restoreConfiguration();

            continue;
        }


        // ====================================================
        // UPDATE
        // ====================================================

        if (choice == "6")
        {
            std::cout
                << "\nUpdate SSH Hardening from GitHub?\n"
                << "The current ssh_hardening.py will be backed up "
                << "before replacement.\n"
                << "The SSH configuration itself will NOT be changed "
                << "by the update.\n"
                << "Continue? [y/N]: ";


            char answer;


            std::cin
                >> answer;


            std::cin.ignore(
                10000,
                '\n'
            );


            if (
                answer == 'y' ||
                answer == 'Y'
                )
            {
                update();
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


        std::cout
            << "Unknown option.\n";
    }
}


// ============================================================
// STATUS
// ============================================================

bool SSHHardening::isEnabled() const
{
    return hardeningEnabled;
}