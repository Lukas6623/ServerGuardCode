#include "SSHKeyGuard.h"

#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>


// ============================================================
// SERVERGUARD SSH KEY GUARD
// ============================================================

static const std::string SSHKEY_SCRIPT =
"/opt/serverguard/ssh_key_guard.py";


static const std::string SSHKEY_SERVICE =
"serverguard-ssh-key.service";


static const std::string SSHKEY_SERVICE_PATH =
"/etc/systemd/system/serverguard-ssh-key.service";


static const std::string SSHKEY_DATA_DIR =
"/opt/serverguard/data";


static const std::string SSHKEY_EVENTS_FILE =
"/opt/serverguard/data/ssh_key_events.json";


static const std::string SSHKEY_STATE_FILE =
"/opt/serverguard/data/ssh_key_state.json";


static const std::string SSHKEY_BACKUP_DIR =
"/opt/serverguard/backups/ssh-key-guard";


static const std::string SSHKEY_BACKUP_SCRIPT =
"/opt/serverguard/backups/ssh-key-guard/ssh_key_guard.py";


static const std::string SSHKEY_TEMP_SCRIPT =
"/opt/serverguard/ssh_key_guard.py.update";


static const std::string SSHKEY_UPDATE_URL =
"https://raw.githubusercontent.com/"
"Lukas6623/ServerGuard/main/"
"ssh_key_guard.py";


static const std::string SSHKEY_AUDIT_RULE =
"/etc/audit/rules.d/"
"serverguard-ssh-key.rules";


// ============================================================
// SYSTEMD SERVICE
// ============================================================

static const std::string SSHKEY_SERVICE_CONTENT = R"([Unit]
Description=ServerGuard SSH Key Guard
After=network-online.target auditd.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

ExecStart=/usr/bin/python3 /opt/serverguard/ssh_key_guard.py monitor --interval 5

WorkingDirectory=/opt/serverguard

Restart=always
RestartSec=5

StandardOutput=journal
StandardError=journal

NoNewPrivileges=false
ProtectSystem=full
ProtectHome=false
PrivateTmp=true

ReadWritePaths=/opt/serverguard/data
ReadWritePaths=/opt/serverguard/backups

[Install]
WantedBy=multi-user.target
)";


// ============================================================
// CONSTRUCTOR
// ============================================================

SSHKeyGuard::SSHKeyGuard(
    LIBSSH2_SESSION* session,
    const std::string& sudoPassword
)
    :
    session(session),
    sudoPassword(sudoPassword)
{}


// ============================================================
// SEPARATOR
// ============================================================

void SSHKeyGuard::printSeparator()
{
    std::cout
        << "========================================"
        << std::endl;
}


// ============================================================
// SHELL QUOTE
// ============================================================

std::string SSHKeyGuard::shellQuote(
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
// BASE64
// ============================================================

std::string SSHKeyGuard::base64Encode(
    const std::string& input
)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string output;

    int val = 0;
    int valb = -6;

    for (unsigned char c : input)
    {
        val =
            (val << 8)
            + c;

        valb += 8;

        while (valb >= 0)
        {
            output.push_back(
                table[
                    (val >> valb)
                        & 0x3F
                ]
            );

            valb -= 6;
        }
    }

    if (valb > -6)
    {
        output.push_back(
            table[
                (
                    (val << 8)
                    >> (valb + 8)
                    )
                    & 0x3F
            ]
        );
    }

    while (
        output.size() % 4
        )
    {
        output.push_back('=');
    }

    return output;
}


// ============================================================
// EXECUTE REMOTE COMMAND
// ============================================================

bool SSHKeyGuard::executeRemote(
    const std::string& command,
    std::string& output,
    int& exitCode
)
{
    output.clear();

    exitCode = -1;

    if (session == nullptr)
    {
        std::cerr
            << "SSH session is not available."
            << std::endl;

        return false;
    }


    std::string remoteCommand =
        command;


    // ========================================================
    // SUDO
    // ========================================================

    if (!sudoPassword.empty())
    {
        std::string encodedPassword =
            base64Encode(
                sudoPassword
            );

        remoteCommand =
            "echo "
            + shellQuote(
                encodedPassword
            )
            + " | base64 -d | "
            "sudo -S -p '' bash -c "
            + shellQuote(
                command
            );
    }


    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(
            session
        );


    if (channel == nullptr)
    {
        std::cerr
            << "Failed to open SSH channel."
            << std::endl;

        return false;
    }


    if (
        libssh2_channel_exec(
            channel,
            remoteCommand.c_str()
        ) != 0
        )
    {
        std::cerr
            << "Failed to execute remote command."
            << std::endl;

        libssh2_channel_free(
            channel
        );

        return false;
    }


    char buffer[4096];


    while (true)
    {
        ssize_t bytesRead =
            libssh2_channel_read(
                channel,
                buffer,
                sizeof(buffer) - 1
            );


        if (bytesRead > 0)
        {
            buffer[bytesRead] =
                '\0';

            output += buffer;

            continue;
        }


        if (bytesRead == 0)
        {
            break;
        }


        if (
            bytesRead ==
            LIBSSH2_ERROR_EAGAIN
            )
        {
            continue;
        }


        break;
    }


    // ========================================================
    // STDERR
    // ========================================================

    while (true)
    {
        ssize_t bytesRead =
            libssh2_channel_read_stderr(
                channel,
                buffer,
                sizeof(buffer) - 1
            );


        if (bytesRead > 0)
        {
            buffer[bytesRead] =
                '\0';

            output += buffer;

            continue;
        }


        if (bytesRead == 0)
        {
            break;
        }


        if (
            bytesRead ==
            LIBSSH2_ERROR_EAGAIN
            )
        {
            continue;
        }


        break;
    }


    libssh2_channel_send_eof(
        channel
    );

    libssh2_channel_wait_eof(
        channel
    );


    exitCode =
        libssh2_channel_get_exit_status(
            channel
        );


    libssh2_channel_close(
        channel
    );

    libssh2_channel_free(
        channel
    );


    return exitCode == 0;
}


// ============================================================
// COMMAND EXISTS
// ============================================================

bool SSHKeyGuard::commandExists(
    const std::string& command
)
{
    std::string output;

    int exitCode = -1;


    std::string check =
        "command -v "
        + shellQuote(command)
        + " >/dev/null 2>&1";


    return executeRemote(
        check,
        output,
        exitCode
    );
}


// ============================================================
// ROOT ACCESS
// ============================================================

bool SSHKeyGuard::checkRootAccess()
{
    std::string output;

    int exitCode = -1;


    // ========================================================
    // DIRECT ROOT / SUDO ROOT TEST
    // ========================================================

    if (
        executeRemote(
            "id -u",
            output,
            exitCode
        )
        )
    {
        std::string uid =
            output;


        uid.erase(
            std::remove_if(
                uid.begin(),
                uid.end(),
                [](unsigned char c)
                {
                    return std::isspace(c);
                }
            ),
            uid.end()
        );


        if (uid == "0")
        {
            return true;
        }
    }


    // ========================================================
    // SUDO
    // ========================================================

    if (sudoPassword.empty())
    {
        std::cout
            << "Root privileges are required."
            << std::endl;

        return false;
    }


    output.clear();

    exitCode = -1;


    if (
        executeRemote(
            "sudo -n true",
            output,
            exitCode
        )
        )
    {
        return true;
    }


    // ========================================================
    // REAL SUDO TEST
    // ========================================================

    output.clear();

    exitCode = -1;


    if (
        executeRemote(
            "true",
            output,
            exitCode
        )
        )
    {
        return true;
    }


    std::cout
        << "Unable to obtain root privileges."
        << std::endl;


    return false;
}


// ============================================================
// SCRIPT EXISTS
// ============================================================

bool SSHKeyGuard::scriptExists()
{
    std::string output;

    int exitCode = -1;


    return executeRemote(
        "test -f "
        + shellQuote(
            SSHKEY_SCRIPT
        ),
        output,
        exitCode
    );
}


// ============================================================
// SERVICE EXISTS
// ============================================================

bool SSHKeyGuard::serviceExists()
{
    std::string output;

    int exitCode = -1;


    return executeRemote(
        "test -f "
        + shellQuote(
            SSHKEY_SERVICE_PATH
        ),
        output,
        exitCode
    );
}


// ============================================================
// SERVICE ACTIVE
// ============================================================

bool SSHKeyGuard::isServiceActive()
{
    std::string output;

    int exitCode = -1;


    return executeRemote(
        "systemctl is-active --quiet "
        + SSHKEY_SERVICE,
        output,
        exitCode
    );
}


// ============================================================
// SERVICE ENABLED
// ============================================================

bool SSHKeyGuard::isServiceEnabled()
{
    std::string output;

    int exitCode = -1;


    return executeRemote(
        "systemctl is-enabled --quiet "
        + SSHKEY_SERVICE,
        output,
        exitCode
    );
}


// ============================================================
// INSTALL PYTHON
// ============================================================

bool SSHKeyGuard::installPython()
{
    if (
        commandExists(
            "python3"
        )
        )
    {
        return true;
    }


    std::cout
        << "Python3 was not found."
        << std::endl;


    std::cout
        << "Installing Python3..."
        << std::endl;


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -y && "
            "apt-get install -y python3",
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    return commandExists(
        "python3"
    );
}


// ============================================================
// INSTALL CURL
// ============================================================

bool SSHKeyGuard::installCurl()
{
    if (
        commandExists(
            "curl"
        )
        )
    {
        return true;
    }


    std::cout
        << "curl was not found."
        << std::endl;


    std::cout
        << "Installing curl..."
        << std::endl;


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -y && "
            "apt-get install -y curl",
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    return commandExists(
        "curl"
    );
}


// ============================================================
// INSTALL AUDITD
// ============================================================

bool SSHKeyGuard::installAuditd()
{
    if (
        commandExists(
            "auditctl"
        )
        )
    {
        std::cout
            << "auditd is already installed."
            << std::endl;

        return true;
    }


    std::cout
        << "auditd was not found."
        << std::endl;


    std::cout
        << "Installing auditd..."
        << std::endl;


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -y && "
            "apt-get install -y auditd audispd-plugins",
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    // ========================================================
    // ENABLE AUDITD
    // ========================================================

    output.clear();

    exitCode = -1;


    executeRemote(
        "systemctl enable auditd",
        output,
        exitCode
    );


    output.clear();

    exitCode = -1;


    executeRemote(
        "systemctl start auditd",
        output,
        exitCode
    );


    return commandExists(
        "auditctl"
    );
}


// ============================================================
// DOWNLOAD SCRIPT
// ============================================================

bool SSHKeyGuard::downloadScript(
    const std::string& url,
    const std::string& destination
)
{
    std::cout
        << "Downloading SSH Key Guard..."
        << std::endl;


    std::string output;

    int exitCode = -1;


    std::string command =
        "curl -fL "
        "--connect-timeout 15 "
        "--max-time 120 "
        "--retry 3 "
        "--silent "
        "--show-error "
        + shellQuote(url)
        + " -o "
        + shellQuote(destination);


    if (
        !executeRemote(
            command,
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "test -s "
            + shellQuote(
                destination
            ),
            output,
            exitCode
        )
        )
    {
        std::cout
            << "Downloaded file is empty."
            << std::endl;

        return false;
    }


    return true;
}


// ============================================================
// VALIDATE PYTHON
// ============================================================

bool SSHKeyGuard::validatePythonScript(
    const std::string& path
)
{
    std::cout
        << "Checking Python syntax..."
        << std::endl;


    std::string output;

    int exitCode = -1;


    std::string command =
        "python3 -m py_compile "
        + shellQuote(path);


    if (
        executeRemote(
            command,
            output,
            exitCode
        )
        )
    {
        return true;
    }


    std::cout
        << "Python syntax validation failed:"
        << std::endl;


    printCommandOutput(
        output
    );


    return false;
}


// ============================================================
// WRITE SYSTEMD SERVICE
// ============================================================

bool SSHKeyGuard::writeServiceFile()
{
    std::cout
        << "Creating systemd service..."
        << std::endl;


    const std::string encoded =
        base64Encode(
            SSHKEY_SERVICE_CONTENT
        );


    std::string output;

    int exitCode = -1;


    std::string command =
        "echo "
        + shellQuote(encoded)
        + " | base64 -d > "
        + shellQuote(
            SSHKEY_SERVICE_PATH
        );


    if (
        !executeRemote(
            command,
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "chmod 644 "
            + shellQuote(
                SSHKEY_SERVICE_PATH
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    return true;
}


// ============================================================
// RELOAD SYSTEMD
// ============================================================

bool SSHKeyGuard::reloadSystemd()
{
    std::cout
        << "Reloading systemd..."
        << std::endl;


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "systemctl daemon-reload",
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    return true;
}


// ============================================================
// ENABLE SERVICE
// ============================================================

bool SSHKeyGuard::enableService()
{
    std::cout
        << "Enabling SSH Key Guard service..."
        << std::endl;


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "systemctl enable "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    return true;
}


// ============================================================
// REMOVE SERVICE FILE
// ============================================================

bool SSHKeyGuard::removeServiceFile()
{
    std::string output;

    int exitCode = -1;


    return executeRemote(
        "rm -f "
        + shellQuote(
            SSHKEY_SERVICE_PATH
        ),
        output,
        exitCode
    );
}


// ============================================================
// BACKUP CURRENT SCRIPT
// ============================================================

bool SSHKeyGuard::backupCurrentScript()
{
    std::cout
        << "Creating backup..."
        << std::endl;


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "mkdir -p "
            + shellQuote(
                SSHKEY_BACKUP_DIR
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "cp "
            + shellQuote(
                SSHKEY_SCRIPT
            )
            + " "
            + shellQuote(
                SSHKEY_BACKUP_SCRIPT
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    return true;
}


// ============================================================
// RESTORE BACKUP
// ============================================================

bool SSHKeyGuard::restoreBackup()
{
    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "test -f "
            + shellQuote(
                SSHKEY_BACKUP_SCRIPT
            ),
            output,
            exitCode
        )
        )
    {
        return false;
    }


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "cp "
            + shellQuote(
                SSHKEY_BACKUP_SCRIPT
            )
            + " "
            + shellQuote(
                SSHKEY_SCRIPT
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return false;
    }


    output.clear();

    exitCode = -1;


    executeRemote(
        "chmod 700 "
        + shellQuote(
            SSHKEY_SCRIPT
        ),
        output,
        exitCode
    );


    return true;
}


// ============================================================
// PRINT OUTPUT
// ============================================================

void SSHKeyGuard::printCommandOutput(
    const std::string& output
)
{
    if (
        output.empty()
        )
    {
        return;
    }


    std::cout
        << output;


    if (
        output.back() != '\n'
        )
    {
        std::cout
            << std::endl;
    }
}


// ============================================================
// INSTALL GUARD
// ============================================================

void SSHKeyGuard::installGuard()
{
    printSeparator();


    std::cout
        << "        INSTALL SSH KEY GUARD"
        << std::endl;


    printSeparator();


    if (
        !checkRootAccess()
        )
    {
        std::cout
            << "Root access is required."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    // ========================================================
    // PYTHON
    // ========================================================

    if (
        !installPython()
        )
    {
        std::cout
            << "Failed to install Python3."
            << std::endl;

        return;
    }


    // ========================================================
    // SYSTEMCTL
    // ========================================================

    if (
        !commandExists(
            "systemctl"
        )
        )
    {
        std::cout
            << "systemctl was not found."
            << std::endl;

        return;
    }


    // ========================================================
    // CURL
    // ========================================================

    if (
        !installCurl()
        )
    {
        std::cout
            << "Failed to install curl."
            << std::endl;

        return;
    }


    // ========================================================
    // AUDITD
    // ========================================================

    std::cout
        << std::endl
        << "Checking auditd..."
        << std::endl;


    if (
        !installAuditd()
        )
    {
        std::cout
            << "Warning: auditd could not be installed."
            << std::endl;

        std::cout
            << "SSH Key Guard will continue using "
            "filesystem monitoring."
            << std::endl;
    }


    // ========================================================
    // DIRECTORIES
    // ========================================================

    std::cout
        << "Creating directories..."
        << std::endl;


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "mkdir -p "
            + shellQuote(
                SSHKEY_DATA_DIR
            )
            + " "
            + shellQuote(
                SSHKEY_BACKUP_DIR
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return;
    }


    // ========================================================
    // DOWNLOAD
    // ========================================================

    if (
        !downloadScript(
            SSHKEY_UPDATE_URL,
            SSHKEY_TEMP_SCRIPT
        )
        )
    {
        std::cout
            << "Failed to download SSH Key Guard."
            << std::endl;

        return;
    }


    // ========================================================
    // VALIDATE
    // ========================================================

    if (
        !validatePythonScript(
            SSHKEY_TEMP_SCRIPT
        )
        )
    {
        executeRemote(
            "rm -f "
            + shellQuote(
                SSHKEY_TEMP_SCRIPT
            ),
            output,
            exitCode
        );

        return;
    }


    // ========================================================
    // BACKUP
    // ========================================================

    if (
        scriptExists()
        )
    {
        std::cout
            << "Existing SSH Key Guard found."
            << std::endl;


        if (
            !backupCurrentScript()
            )
        {
            std::cout
                << "Warning: backup could not be created."
                << std::endl;
        }
    }


    // ========================================================
    // INSTALL SCRIPT
    // ========================================================

    std::cout
        << "Installing SSH Key Guard script..."
        << std::endl;


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "mv "
            + shellQuote(
                SSHKEY_TEMP_SCRIPT
            )
            + " "
            + shellQuote(
                SSHKEY_SCRIPT
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return;
    }


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "chmod 700 "
            + shellQuote(
                SSHKEY_SCRIPT
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return;
    }


    // ========================================================
    // INITIAL BASELINE
    // ========================================================

    std::cout
        << "Creating SSH key baseline..."
        << std::endl;


    output.clear();

    exitCode = -1;


    executeRemote(
        "python3 "
        + shellQuote(
            SSHKEY_SCRIPT
        )
        + " init",
        output,
        exitCode
    );


    printCommandOutput(
        output
    );


    // ========================================================
    // SYSTEMD
    // ========================================================

    if (
        !writeServiceFile()
        )
    {
        std::cout
            << "Failed to create systemd service."
            << std::endl;

        return;
    }


    // ========================================================
    // RELOAD
    // ========================================================

    if (
        !reloadSystemd()
        )
    {
        return;
    }


    // ========================================================
    // ENABLE
    // ========================================================

    if (
        !enableService()
        )
    {
        return;
    }


    // ========================================================
    // START
    // ========================================================

    std::cout
        << "Starting SSH Key Guard..."
        << std::endl;


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "systemctl restart "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        std::cout
            << "Failed to start SSH Key Guard."
            << std::endl;

        printCommandOutput(
            output
        );

        return;
    }


    // ========================================================
    // VERIFY
    // ========================================================

    std::cout
        << "Checking service..."
        << std::endl;


    if (
        !isServiceActive()
        )
    {
        std::cout
            << std::endl
            << "SSH Key Guard failed to start."
            << std::endl;


        output.clear();

        exitCode = -1;


        executeRemote(
            "systemctl status "
            + SSHKEY_SERVICE
            + " --no-pager",
            output,
            exitCode
        );


        printCommandOutput(
            output
        );


        std::cout
            << std::endl
            << "Recent logs:"
            << std::endl;


        output.clear();

        exitCode = -1;


        executeRemote(
            "journalctl -u "
            + SSHKEY_SERVICE
            + " -n 30 --no-pager",
            output,
            exitCode
        );


        printCommandOutput(
            output
        );


        return;
    }


    printSeparator();


    std::cout
        << "SSH Key Guard installed successfully."
        << std::endl;


    std::cout
        << "Service: ACTIVE"
        << std::endl;


    std::cout
        << "Enabled: "
        << (
            isServiceEnabled()
            ? "YES"
            : "NO"
            )
        << std::endl;


    std::cout
        << "Script: EXISTS"
        << std::endl;


    std::cout
        << "Auditd: "
        << (
            commandExists("auditctl")
            ? "AVAILABLE"
            : "NOT AVAILABLE"
            )
        << std::endl;


    printSeparator();
}


// ============================================================
// REMOVE GUARD
// ============================================================

void SSHKeyGuard::removeGuard()
{
    printSeparator();


    std::cout
        << "          REMOVE SSH KEY GUARD"
        << std::endl;


    printSeparator();


    if (
        !checkRootAccess()
        )
    {
        return;
    }


    std::string output;

    int exitCode = -1;


    // ========================================================
    // STOP
    // ========================================================

    std::cout
        << "Stopping service..."
        << std::endl;


    executeRemote(
        "systemctl stop "
        + SSHKEY_SERVICE,
        output,
        exitCode
    );


    // ========================================================
    // DISABLE
    // ========================================================

    output.clear();

    exitCode = -1;


    executeRemote(
        "systemctl disable "
        + SSHKEY_SERVICE,
        output,
        exitCode
    );


    // ========================================================
    // REMOVE SERVICE
    // ========================================================

    std::cout
        << "Removing systemd service..."
        << std::endl;


    if (
        !removeServiceFile()
        )
    {
        std::cout
            << "Failed to remove service file."
            << std::endl;

        return;
    }


    if (
        !reloadSystemd()
        )
    {
        return;
    }


    // ========================================================
    // REMOVE SCRIPT
    // ========================================================

    std::cout
        << "Removing SSH Key Guard script..."
        << std::endl;


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "rm -f "
            + shellQuote(
                SSHKEY_SCRIPT
            )
            + " "
            + shellQuote(
                SSHKEY_TEMP_SCRIPT
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return;
    }


    // ========================================================
    // REMOVE AUDIT RULE
    // ========================================================

    std::cout
        << "Removing ServerGuard audit rules..."
        << std::endl;


    output.clear();

    exitCode = -1;


    executeRemote(
        "rm -f "
        + shellQuote(
            SSHKEY_AUDIT_RULE
        ),
        output,
        exitCode
    );


    // ========================================================
    // RELOAD AUDIT
    // ========================================================

    output.clear();

    exitCode = -1;


    executeRemote(
        "command -v augenrules >/dev/null 2>&1 && "
        "augenrules --load >/dev/null 2>&1 || true",
        output,
        exitCode
    );


    printSeparator();


    std::cout
        << "SSH Key Guard removed."
        << std::endl;


    std::cout
        << "Monitoring data was preserved:"
        << std::endl;


    std::cout
        << SSHKEY_DATA_DIR
        << std::endl;


    std::cout
        << "Backups were preserved:"
        << std::endl;


    std::cout
        << SSHKEY_BACKUP_DIR
        << std::endl;


    printSeparator();
}


// ============================================================
// START
// ============================================================

void SSHKeyGuard::startGuard()
{
    printSeparator();


    std::cout
        << "          START SSH KEY GUARD"
        << std::endl;


    printSeparator();


    if (
        !checkRootAccess()
        )
    {
        return;
    }


    if (
        !serviceExists()
        )
    {
        std::cout
            << "SSH Key Guard is not installed."
            << std::endl;


        std::cout
            << "Install it first."
            << std::endl;


        return;
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "systemctl start "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        std::cout
            << "Failed to start SSH Key Guard."
            << std::endl;


        printCommandOutput(
            output
        );


        return;
    }


    if (
        isServiceActive()
        )
    {
        std::cout
            << "SSH Key Guard started successfully."
            << std::endl;


        std::cout
            << "Service: ACTIVE"
            << std::endl;
    }
    else
    {
        std::cout
            << "SSH Key Guard did not become active."
            << std::endl;
    }
}


// ============================================================
// STOP
// ============================================================

void SSHKeyGuard::stopGuard()
{
    printSeparator();


    std::cout
        << "           STOP SSH KEY GUARD"
        << std::endl;


    printSeparator();


    if (
        !checkRootAccess()
        )
    {
        return;
    }


    if (
        !serviceExists()
        )
    {
        std::cout
            << "SSH Key Guard is not installed."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "systemctl stop "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return;
    }


    std::cout
        << "SSH Key Guard stopped."
        << std::endl;
}


// ============================================================
// RESTART
// ============================================================

void SSHKeyGuard::restartGuard()
{
    printSeparator();


    std::cout
        << "         RESTART SSH KEY GUARD"
        << std::endl;


    printSeparator();


    if (
        !checkRootAccess()
        )
    {
        return;
    }


    if (
        !serviceExists()
        )
    {
        std::cout
            << "SSH Key Guard is not installed."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "systemctl restart "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        std::cout
            << "Failed to restart SSH Key Guard."
            << std::endl;


        printCommandOutput(
            output
        );


        return;
    }


    if (
        isServiceActive()
        )
    {
        std::cout
            << "SSH Key Guard restarted successfully."
            << std::endl;


        std::cout
            << "Service: ACTIVE"
            << std::endl;
    }
    else
    {
        std::cout
            << "SSH Key Guard failed to become active."
            << std::endl;


        output.clear();

        exitCode = -1;


        executeRemote(
            "journalctl -u "
            + SSHKEY_SERVICE
            + " -n 30 --no-pager",
            output,
            exitCode
        );


        printCommandOutput(
            output
        );
    }
}


// ============================================================
// STATUS
// ============================================================

void SSHKeyGuard::showStatus()
{
    printSeparator();


    std::cout
        << "          SSH KEY GUARD STATUS"
        << std::endl;


    printSeparator();


    bool installed =
        serviceExists();


    bool script =
        scriptExists();


    bool audit =
        commandExists(
            "auditctl"
        );


    std::cout
        << "Service: "
        << (
            installed
            ? "INSTALLED"
            : "NOT INSTALLED"
            )
        << std::endl;


    std::cout
        << "Script: "
        << (
            script
            ? "EXISTS"
            : "NOT FOUND"
            )
        << std::endl;


    std::cout
        << "Auditd: "
        << (
            audit
            ? "AVAILABLE"
            : "NOT AVAILABLE"
            )
        << std::endl;


    if (
        installed
        )
    {
        std::cout
            << "State: "
            << (
                isServiceActive()
                ? "ACTIVE"
                : "INACTIVE"
                )
            << std::endl;


        std::cout
            << "Enabled: "
            << (
                isServiceEnabled()
                ? "YES"
                : "NO"
                )
            << std::endl;
    }


    std::cout
        << "Script path: "
        << SSHKEY_SCRIPT
        << std::endl;


    std::cout
        << "Events: "
        << SSHKEY_EVENTS_FILE
        << std::endl;


    std::cout
        << "State: "
        << SSHKEY_STATE_FILE
        << std::endl;


    printSeparator();


    if (
        installed
        &&
        !isServiceActive()
        )
    {
        std::cout
            << std::endl
            << "Recent service logs:"
            << std::endl;


        std::string output;

        int exitCode = -1;


        executeRemote(
            "journalctl -u "
            + SSHKEY_SERVICE
            + " -n 30 --no-pager",
            output,
            exitCode
        );


        printCommandOutput(
            output
        );
    }
}


// ============================================================
// INITIALIZE BASELINE
// ============================================================

void SSHKeyGuard::initializeBaseline()
{
    printSeparator();


    std::cout
        << "       CREATE SSH KEY BASELINE"
        << std::endl;


    printSeparator();


    if (
        !scriptExists()
        )
    {
        std::cout
            << "SSH Key Guard is not installed."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "python3 "
            + shellQuote(
                SSHKEY_SCRIPT
            )
            + " init",
            output,
            exitCode
        )
        )
    {
        std::cout
            << "Failed to create baseline."
            << std::endl;


        printCommandOutput(
            output
        );


        return;
    }


    printCommandOutput(
        output
    );
}


// ============================================================
// SCAN NOW
// ============================================================

void SSHKeyGuard::scanNow()
{
    printSeparator();


    std::cout
        << "          SCAN SSH KEYS"
        << std::endl;


    printSeparator();


    if (
        !scriptExists()
        )
    {
        std::cout
            << "SSH Key Guard is not installed."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "python3 "
            + shellQuote(
                SSHKEY_SCRIPT
            )
            + " scan",
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return;
    }


    printCommandOutput(
        output
    );
}


// ============================================================
// EVENTS
// ============================================================

void SSHKeyGuard::showEvents()
{
    printSeparator();


    std::cout
        << "          SSH KEY EVENTS"
        << std::endl;


    printSeparator();


    if (
        !scriptExists()
        )
    {
        std::cout
            << "SSH Key Guard is not installed."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "python3 "
            + shellQuote(
                SSHKEY_SCRIPT
            )
            + " events 50",
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return;
    }


    printCommandOutput(
        output
    );
}


// ============================================================
// LOGS
// ============================================================

void SSHKeyGuard::showLogs()
{
    printSeparator();


    std::cout
        << "        SSH KEY GUARD SERVICE LOGS"
        << std::endl;


    printSeparator();


    if (
        !serviceExists()
        )
    {
        std::cout
            << "Service is not installed."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    executeRemote(
        "journalctl -u "
        + SSHKEY_SERVICE
        + " -n 100 --no-pager",
        output,
        exitCode
    );


    printCommandOutput(
        output
    );
}


// ============================================================
// INSTALL AUDIT
// ============================================================

void SSHKeyGuard::installAudit()
{
    printSeparator();


    std::cout
        << "          INSTALL AUDIT SUPPORT"
        << std::endl;


    printSeparator();


    if (
        !checkRootAccess()
        )
    {
        return;
    }


    if (
        !installAuditd()
        )
    {
        std::cout
            << "Failed to install auditd."
            << std::endl;

        return;
    }


    if (
        !scriptExists()
        )
    {
        std::cout
            << "SSH Key Guard script is not installed."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    // ========================================================
    // LET PYTHON GUARD CREATE RULES
    // ========================================================

    if (
        executeRemote(
            "python3 "
            + shellQuote(
                SSHKEY_SCRIPT
            )
            + " audit",
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );
    }
    else
    {
        printCommandOutput(
            output
        );


        std::cout
            << "Audit rule setup reported an error."
            << std::endl;
    }


    // ========================================================
    // AUDIT STATUS
    // ========================================================

    output.clear();

    exitCode = -1;


    executeRemote(
        "auditctl -s",
        output,
        exitCode
    );


    printSeparator();


    std::cout
        << "Audit status:"
        << std::endl;


    printCommandOutput(
        output
    );


    printSeparator();
}


// ============================================================
// UPDATE
// ============================================================

void SSHKeyGuard::updateGuard()
{
    printSeparator();


    std::cout
        << "          UPDATE SSH KEY GUARD"
        << std::endl;


    printSeparator();


    if (
        !checkRootAccess()
        )
    {
        return;
    }


    if (
        !scriptExists()
        )
    {
        std::cout
            << "SSH Key Guard is not installed."
            << std::endl;


        std::cout
            << "Install it first."
            << std::endl;


        return;
    }


    if (
        !installCurl()
        )
    {
        std::cout
            << "curl is required."
            << std::endl;

        return;
    }


    std::string output;

    int exitCode = -1;


    // ========================================================
    // DOWNLOAD
    // ========================================================

    if (
        !downloadScript(
            SSHKEY_UPDATE_URL,
            SSHKEY_TEMP_SCRIPT
        )
        )
    {
        std::cout
            << "Failed to download update."
            << std::endl;

        return;
    }


    // ========================================================
    // VALIDATE
    // ========================================================

    if (
        !validatePythonScript(
            SSHKEY_TEMP_SCRIPT
        )
        )
    {
        executeRemote(
            "rm -f "
            + shellQuote(
                SSHKEY_TEMP_SCRIPT
            ),
            output,
            exitCode
        );


        std::cout
            << "Update cancelled."
            << std::endl;


        return;
    }


    // ========================================================
    // BACKUP
    // ========================================================

    if (
        !backupCurrentScript()
        )
    {
        std::cout
            << "Failed to create backup."
            << std::endl;


        executeRemote(
            "rm -f "
            + shellQuote(
                SSHKEY_TEMP_SCRIPT
            ),
            output,
            exitCode
        );


        return;
    }


    // ========================================================
    // INSTALL
    // ========================================================

    std::cout
        << "Installing update..."
        << std::endl;


    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "mv "
            + shellQuote(
                SSHKEY_TEMP_SCRIPT
            )
            + " "
            + shellQuote(
                SSHKEY_SCRIPT
            ),
            output,
            exitCode
        )
        )
    {
        printCommandOutput(
            output
        );

        return;
    }


    output.clear();

    exitCode = -1;


    executeRemote(
        "chmod 700 "
        + shellQuote(
            SSHKEY_SCRIPT
        ),
        output,
        exitCode
    );


    // ========================================================
    // RESTART
    // ========================================================

    if (
        serviceExists()
        )
    {
        std::cout
            << "Restarting SSH Key Guard..."
            << std::endl;


        output.clear();

        exitCode = -1;


        if (
            !executeRemote(
                "systemctl restart "
                + SSHKEY_SERVICE,
                output,
                exitCode
            )
            )
        {
            std::cout
                << "Updated SSH Key Guard failed to start."
                << std::endl;


            printCommandOutput(
                output
            );


            // =================================================
            // ROLLBACK
            // =================================================

            std::cout
                << "Restoring previous version..."
                << std::endl;


            if (
                restoreBackup()
                )
            {
                output.clear();

                exitCode = -1;


                executeRemote(
                    "systemctl restart "
                    + SSHKEY_SERVICE,
                    output,
                    exitCode
                );


                if (
                    isServiceActive()
                    )
                {
                    std::cout
                        << "Previous version restored successfully."
                        << std::endl;
                }
                else
                {
                    std::cout
                        << "Previous version was restored, "
                        "but service is not active."
                        << std::endl;
                }
            }


            return;
        }


        if (
            !isServiceActive()
            )
        {
            std::cout
                << "Updated SSH Key Guard is not active."
                << std::endl;


            std::cout
                << "Restoring previous version..."
                << std::endl;


            if (
                restoreBackup()
                )
            {
                output.clear();

                exitCode = -1;


                executeRemote(
                    "systemctl restart "
                    + SSHKEY_SERVICE,
                    output,
                    exitCode
                );


                if (
                    isServiceActive()
                    )
                {
                    std::cout
                        << "Previous version restored successfully."
                        << std::endl;
                }
            }


            return;
        }
    }


    printSeparator();


    std::cout
        << "SSH Key Guard updated successfully."
        << std::endl;


    if (
        serviceExists()
        )
    {
        std::cout
            << "Service: ACTIVE"
            << std::endl;
    }


    printSeparator();
}


// ============================================================
// MENU
// ============================================================

void SSHKeyGuard::menu()
{
    while (true)
    {
        std::cout
            << std::endl;


        printSeparator();


        std::cout
            << "          SERVERGUARD SSH KEY GUARD"
            << std::endl;


        printSeparator();


        std::cout
            << "1. Install / enable SSH Key Guard"
            << std::endl;


        std::cout
            << "2. Remove SSH Key Guard"
            << std::endl;


        std::cout
            << "3. Start SSH Key Guard"
            << std::endl;


        std::cout
            << "4. Stop SSH Key Guard"
            << std::endl;


        std::cout
            << "5. Restart SSH Key Guard"
            << std::endl;


        std::cout
            << "6. SSH Key Guard status"
            << std::endl;


        std::cout
            << "7. Create SSH key baseline"
            << std::endl;


        std::cout
            << "8. Scan SSH keys now"
            << std::endl;


        std::cout
            << "9. SSH key events"
            << std::endl;


        std::cout
            << "10. Show service logs"
            << std::endl;


        std::cout
            << "11. Install / configure auditd"
            << std::endl;


        std::cout
            << "12. Update SSH Key Guard"
            << std::endl;


        std::cout
            << "0. Back"
            << std::endl;


        printSeparator();


        std::cout
            << "Select: ";


        int choice;


        if (
            !(std::cin >> choice)
            )
        {
            std::cin.clear();


            std::cin.ignore(
                10000,
                '\n'
            );


            std::cout
                << "Invalid selection."
                << std::endl;


            continue;
        }


        switch (choice)
        {
        case 1:

            installGuard();

            break;


        case 2:

            removeGuard();

            break;


        case 3:

            startGuard();

            break;


        case 4:

            stopGuard();

            break;


        case 5:

            restartGuard();

            break;


        case 6:

            showStatus();

            break;


        case 7:

            initializeBaseline();

            break;


        case 8:

            scanNow();

            break;


        case 9:

            showEvents();

            break;


        case 10:

            showLogs();

            break;


        case 11:

            installAudit();

            break;


        case 12:

            updateGuard();

            break;


        case 0:

            return;


        default:

            std::cout
                << "Unknown option."
                << std::endl;

            break;
        }
    }
}


// ============================================================
// WEB INTERFACE
// ============================================================


// ============================================================
// WEB INSTALL
// ============================================================

bool SSHKeyGuard::webInstall()
{
    installGuard();


    if (!serviceExists())
    {
        return false;
    }


    if (!scriptExists())
    {
        return false;
    }


    return
        isServiceActive()
        &&
        isServiceEnabled();
}


// ============================================================
// WEB REMOVE
// ============================================================

bool SSHKeyGuard::webRemove()
{
    removeGuard();


    return
        !serviceExists()
        &&
        !scriptExists();
}


// ============================================================
// WEB START
// ============================================================

bool SSHKeyGuard::webStart()
{
    if (!serviceExists())
    {
        return false;
    }


    std::string output;

    int exitCode = -1;


    // ========================================================
    // ENABLE SERVICE
    // ========================================================

    if (
        !executeRemote(
            "systemctl enable "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        return false;
    }


    // ========================================================
    // START SERVICE
    // ========================================================

    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "systemctl start "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        return false;
    }


    // ========================================================
    // VERIFY
    // ========================================================

    return
        isServiceActive()
        &&
        isServiceEnabled();
}


// ============================================================
// WEB STOP / DISABLE
// ============================================================

bool SSHKeyGuard::webStop()
{
    if (!serviceExists())
    {
        return false;
    }


    std::string output;

    int exitCode = -1;


    // ========================================================
    // STOP SERVICE
    // ========================================================

    if (
        !executeRemote(
            "systemctl stop "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        return false;
    }


    // ========================================================
    // DISABLE SERVICE
    // ========================================================

    output.clear();

    exitCode = -1;


    if (
        !executeRemote(
            "systemctl disable "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        return false;
    }


    // ========================================================
    // VERIFY REAL SYSTEMD STATE
    // ========================================================

    bool active =
        isServiceActive();


    bool enabled =
        isServiceEnabled();


    return
        !active
        &&
        !enabled;
}


// ============================================================
// WEB RESTART
// ============================================================

bool SSHKeyGuard::webRestart()
{
    if (!serviceExists())
    {
        return false;
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "systemctl restart "
            + SSHKEY_SERVICE,
            output,
            exitCode
        )
        )
    {
        return false;
    }


    return isServiceActive();
}


// ============================================================
// WEB STATUS
// ============================================================

std::string SSHKeyGuard::webStatus()
{
    bool installed =
        serviceExists();


    bool script =
        scriptExists();


    bool audit =
        commandExists(
            "auditctl"
        );


    bool active = false;

    bool enabled = false;


    if (installed)
    {
        active =
            isServiceActive();


        enabled =
            isServiceEnabled();
    }


    std::string json;


    json += "{";


    json +=
        "\"installed\":"
        +
        std::string(
            installed
            ? "true"
            : "false"
        );


    json += ",";


    json +=
        "\"script\":"
        +
        std::string(
            script
            ? "true"
            : "false"
        );


    json += ",";


    json +=
        "\"active\":"
        +
        std::string(
            active
            ? "true"
            : "false"
        );


    json += ",";


    json +=
        "\"enabled\":"
        +
        std::string(
            enabled
            ? "true"
            : "false"
        );


    json += ",";


    json +=
        "\"auditd\":"
        +
        std::string(
            audit
            ? "true"
            : "false"
        );


    json += ",";


    json +=
        "\"script_path\":\""
        +
        SSHKEY_SCRIPT
        +
        "\"";


    json += ",";


    json +=
        "\"events_file\":\""
        +
        SSHKEY_EVENTS_FILE
        +
        "\"";


    json += ",";


    json +=
        "\"state_file\":\""
        +
        SSHKEY_STATE_FILE
        +
        "\"";


    json += ",";


    json +=
        "\"service\":\""
        +
        SSHKEY_SERVICE
        +
        "\"";


    json += "}";


    return json;
}


// ============================================================
// WEB BASELINE
// ============================================================

bool SSHKeyGuard::webBaseline()
{
    if (!scriptExists())
    {
        return false;
    }


    std::string output;

    int exitCode = -1;


    return executeRemote(
        "python3 "
        + shellQuote(
            SSHKEY_SCRIPT
        )
        + " init",
        output,
        exitCode
    );
}


// ============================================================
// WEB SCAN
// ============================================================

bool SSHKeyGuard::webScan()
{
    if (!scriptExists())
    {
        return false;
    }


    std::string output;

    int exitCode = -1;


    return executeRemote(
        "python3 "
        + shellQuote(
            SSHKEY_SCRIPT
        )
        + " scan",
        output,
        exitCode
    );
}


// ============================================================
// WEB EVENTS
// ============================================================

std::string SSHKeyGuard::webEvents()
{
    if (!scriptExists())
    {
        return "SSH Key Guard is not installed.";
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "python3 "
            + shellQuote(
                SSHKEY_SCRIPT
            )
            + " events 50",
            output,
            exitCode
        )
        )
    {
        if (output.empty())
        {
            return "Failed to get SSH key events.";
        }
    }


    return output;
}


// ============================================================
// WEB LOGS
// ============================================================

std::string SSHKeyGuard::webLogs()
{
    if (!serviceExists())
    {
        return "SSH Key Guard service is not installed.";
    }


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            "journalctl -u "
            + SSHKEY_SERVICE
            + " -n 100 --no-pager",
            output,
            exitCode
        )
        )
    {
        if (output.empty())
        {
            return "Failed to get SSH Key Guard logs.";
        }
    }


    return output;
}


// ============================================================
// WEB AUDIT
// ============================================================

bool SSHKeyGuard::webAudit()
{
    if (!checkRootAccess())
    {
        return false;
    }


    if (!installAuditd())
    {
        return false;
    }


    if (!scriptExists())
    {
        return false;
    }


    std::string output;

    int exitCode = -1;


    return executeRemote(
        "python3 "
        + shellQuote(
            SSHKEY_SCRIPT
        )
        + " audit",
        output,
        exitCode
    );
}


// ============================================================
// WEB UPDATE
// ============================================================

bool SSHKeyGuard::webUpdate()
{
    updateGuard();


    return
        scriptExists()
        &&
        (
            !serviceExists()
            ||
            isServiceActive()
            );
}