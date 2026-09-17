#include "FileGuard.h"

#include <libssh2.h>

#include <algorithm>
#include <iostream>
#include <string>


// ============================================================
// CONFIGURATION
// ============================================================

static const std::string FILEGUARD_DATA_DIR =
"/opt/serverguard/data";

static const std::string FILEGUARD_SCRIPT =
"/opt/serverguard/file_guard.py";

static const std::string FILEGUARD_SERVICE =
"serverguard-fileguard.service";

static const std::string FILEGUARD_SERVICE_PATH =
"/etc/systemd/system/serverguard-fileguard.service";


// ============================================================
// UPDATE CONFIGURATION
// ============================================================

static const std::string FILEGUARD_UPDATE_URL =
"https://raw.githubusercontent.com/"
"Lukas6623/ServerGuard/main/file_guard.py";

static const std::string FILEGUARD_TEMP_SCRIPT =
"/opt/serverguard/file_guard.py.update";

static const std::string FILEGUARD_BACKUP_DIR =
"/opt/serverguard/backups/fileguard";

static const std::string FILEGUARD_BACKUP_SCRIPT =
"/opt/serverguard/backups/fileguard/file_guard.py";


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
// CONSTRUCTOR
// ============================================================

FileGuard::FileGuard(
    LIBSSH2_SESSION* session,
    const std::string& sudoPassword)
    :
    session(session),
    sudoPassword(sudoPassword)
{}


// ============================================================
// EXECUTE REMOTE COMMAND
// ============================================================

bool FileGuard::executeRemote(
    const std::string& command,
    std::string* output)
{
    if (!session)
    {
        std::cout
            << "Invalid SSH session.\n";

        return false;
    }


    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(session);

    if (!channel)
    {
        std::cout
            << "Cannot open SSH channel.\n";

        return false;
    }


    std::string finalCommand =
        command;


    // ========================================================
    // SUDO
    // ========================================================

    if (!sudoPassword.empty())
    {
        const std::string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";


        const unsigned char* data =
            reinterpret_cast<
            const unsigned char*
            >(sudoPassword.data());


        size_t len =
            sudoPassword.size();


        std::string encodedPassword;


        for (size_t i = 0; i < len; i += 3)
        {
            unsigned int value = 0;


            value |=
                static_cast<unsigned int>(
                    data[i]
                    ) << 16;


            if (i + 1 < len)
            {
                value |=
                    static_cast<unsigned int>(
                        data[i + 1]
                        ) << 8;
            }


            if (i + 2 < len)
            {
                value |=
                    static_cast<unsigned int>(
                        data[i + 2]
                        );
            }


            encodedPassword +=
                alphabet[
                    (value >> 18) & 0x3F
                ];


            encodedPassword +=
                alphabet[
                    (value >> 12) & 0x3F
                ];


            if (i + 1 < len)
            {
                encodedPassword +=
                    alphabet[
                        (value >> 6) & 0x3F
                    ];
            }
            else
            {
                encodedPassword += '=';
            }


            if (i + 2 < len)
            {
                encodedPassword +=
                    alphabet[
                        value & 0x3F
                    ];
            }
            else
            {
                encodedPassword += '=';
            }
        }


        finalCommand =
            "echo " +
            shellQuote(encodedPassword) +
            " | base64 -d | sudo -S -p '' bash -c " +
            shellQuote(command);
    }


    // ========================================================
    // EXECUTE
    // ========================================================

    if (libssh2_channel_exec(
        channel,
        finalCommand.c_str()) != 0)
    {
        std::cout
            << "Cannot execute remote command.\n";

        libssh2_channel_free(channel);

        return false;
    }


    char buffer[4096];

    std::string result;


    // ========================================================
    // STDOUT
    // ========================================================

    while (true)
    {
        int rc =
            libssh2_channel_read(
                channel,
                buffer,
                sizeof(buffer) - 1);

        if (rc > 0)
        {
            buffer[rc] = '\0';

            result += buffer;
        }
        else
        {
            break;
        }
    }


    // ========================================================
    // STDERR
    // ========================================================

    while (true)
    {
        int rc =
            libssh2_channel_read_stderr(
                channel,
                buffer,
                sizeof(buffer) - 1);

        if (rc > 0)
        {
            buffer[rc] = '\0';

            result += buffer;
        }
        else
        {
            break;
        }
    }


    libssh2_channel_send_eof(channel);

    libssh2_channel_wait_eof(channel);

    libssh2_channel_wait_closed(channel);


    int exitCode =
        libssh2_channel_get_exit_status(
            channel);


    libssh2_channel_free(channel);


    if (output)
    {
        *output = result;
    }


    return exitCode == 0;
}


// ============================================================
// ROOT / SUDO CHECK
// ============================================================

bool FileGuard::checkRootOrSudo()
{
    std::string output;


    if (executeRemote(
        "id -u",
        &output))
    {
        std::string value =
            output;


        value.erase(
            std::remove(
                value.begin(),
                value.end(),
                '\n'),
            value.end());


        value.erase(
            std::remove(
                value.begin(),
                value.end(),
                '\r'),
            value.end());


        if (value == "0")
        {
            return true;
        }
    }


    if (sudoPassword.empty())
    {
        std::cout
            << "Root privileges are required.\n";

        return false;
    }


    if (executeRemote(
        "sudo -S -p '' -v",
        &output))
    {
        return true;
    }


    std::cout
        << "Cannot obtain sudo privileges.\n";


    return false;
}


// ============================================================
// COMMAND EXISTS
// ============================================================

bool FileGuard::commandExists(
    const std::string& command)
{
    std::string output;


    return executeRemote(
        "command -v " +
        shellQuote(command) +
        " >/dev/null 2>&1",
        &output);
}


// ============================================================
// CREATE DIRECTORIES
// ============================================================

bool FileGuard::createDirectories()
{
    std::cout
        << "[1/6] Creating directories...\n";


    return executeRemote(
        "mkdir -p " +
        shellQuote(FILEGUARD_DATA_DIR));
}


// ============================================================
// SET PERMISSIONS
// ============================================================

bool FileGuard::setPermissions()
{
    std::cout
        << "[2/6] Setting permissions...\n";


    if (!executeRemote(
        "chown root:root " +
        shellQuote(FILEGUARD_SCRIPT)))
    {
        return false;
    }


    if (!executeRemote(
        "chmod 700 " +
        shellQuote(FILEGUARD_SCRIPT)))
    {
        return false;
    }


    if (!executeRemote(
        "chown root:root " +
        shellQuote(FILEGUARD_DATA_DIR)))
    {
        return false;
    }


    if (!executeRemote(
        "chmod 700 " +
        shellQuote(FILEGUARD_DATA_DIR)))
    {
        return false;
    }


    return true;
}


// ============================================================
// CREATE SYSTEMD SERVICE
// ============================================================

bool FileGuard::createSystemdService()
{
    std::cout
        << "[3/6] Creating systemd service...\n";


    const std::string service =
        R"(# ServerGuard FileGuard
[Unit]
Description=ServerGuard File Integrity Protection
After=network.target

[Service]
Type=simple

ExecStart=/usr/bin/python3 /opt/serverguard/file_guard.py

Restart=always
RestartSec=5

User=root
Group=root

WorkingDirectory=/opt/serverguard

NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
)";


    // ========================================================
    // BASE64 ENCODE SERVICE
    // ========================================================

    const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";


    std::string encoded;


    for (size_t i = 0; i < service.size(); i += 3)
    {
        unsigned int value = 0;


        value |=
            static_cast<unsigned int>(
                static_cast<unsigned char>(
                    service[i]
                    )
                ) << 16;


        if (i + 1 < service.size())
        {
            value |=
                static_cast<unsigned int>(
                    static_cast<unsigned char>(
                        service[i + 1]
                        )
                    ) << 8;
        }


        if (i + 2 < service.size())
        {
            value |=
                static_cast<unsigned int>(
                    static_cast<unsigned char>(
                        service[i + 2]
                        )
                    );
        }


        encoded +=
            alphabet[
                (value >> 18) & 0x3F
            ];


        encoded +=
            alphabet[
                (value >> 12) & 0x3F
            ];


        if (i + 1 < service.size())
        {
            encoded +=
                alphabet[
                    (value >> 6) & 0x3F
                ];
        }
        else
        {
            encoded += '=';
        }


        if (i + 2 < service.size())
        {
            encoded +=
                alphabet[
                    value & 0x3F
                ];
        }
        else
        {
            encoded += '=';
        }
    }


    // ========================================================
    // WRITE SERVICE
    // ========================================================

    std::string command =
        "echo " +
        shellQuote(encoded) +
        " | base64 -d > " +
        shellQuote(FILEGUARD_SERVICE_PATH);


    if (!executeRemote(command))
    {
        return false;
    }


    if (!executeRemote(
        "chmod 644 " +
        shellQuote(FILEGUARD_SERVICE_PATH)))
    {
        return false;
    }


    return true;
}


// ============================================================
// RELOAD SYSTEMD
// ============================================================

bool FileGuard::reloadSystemd()
{
    std::cout
        << "[4/6] Reloading systemd...\n";


    return executeRemote(
        "systemctl daemon-reload");
}


// ============================================================
// ENABLE SERVICE
// ============================================================

bool FileGuard::enableService()
{
    std::cout
        << "[5/6] Enabling service...\n";


    return executeRemote(
        "systemctl enable " +
        shellQuote(FILEGUARD_SERVICE));
}


// ============================================================
// START SERVICE
// ============================================================

bool FileGuard::startService()
{
    std::cout
        << "[6/6] Starting service...\n";


    return executeRemote(
        "systemctl restart " +
        shellQuote(FILEGUARD_SERVICE));
}


// ============================================================
// STOP SERVICE
// ============================================================

bool FileGuard::stopService()
{
    return executeRemote(
        "systemctl stop " +
        shellQuote(FILEGUARD_SERVICE));
}


// ============================================================
// DISABLE SERVICE
// ============================================================

bool FileGuard::disableService()
{
    return executeRemote(
        "systemctl disable " +
        shellQuote(FILEGUARD_SERVICE));
}


// ============================================================
// SERVICE EXISTS
// ============================================================

bool FileGuard::serviceExists()
{
    std::string output;


    return executeRemote(
        "systemctl list-unit-files " +
        shellQuote(FILEGUARD_SERVICE) +
        " --no-legend | grep -q " +
        shellQuote(FILEGUARD_SERVICE),
        &output);
}


// ============================================================
// SERVICE IS ACTIVE
// ============================================================

bool FileGuard::serviceIsActive()
{
    std::string output;


    return executeRemote(
        "systemctl is-active --quiet " +
        shellQuote(FILEGUARD_SERVICE),
        &output);
}


// ============================================================
// INSTALL
// ============================================================

bool FileGuard::install()
{
    std::cout
        << "\n========================================\n"
        << "      INSTALL SERVERGUARD FILEGUARD\n"
        << "========================================\n\n";


    // ========================================================
    // ROOT
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
            << "Python3 is not installed.\n";

        return false;
    }


    // ========================================================
    // SYSTEMCTL
    // ========================================================

    if (!commandExists("systemctl"))
    {
        std::cout
            << "systemctl is not available.\n";

        return false;
    }


    // ========================================================
    // BASE64
    // ========================================================

    if (!commandExists("base64"))
    {
        std::cout
            << "base64 is not available.\n";

        return false;
    }


    // ========================================================
    // CREATE DIRECTORIES
    // ========================================================

    if (!createDirectories())
    {
        std::cout
            << "Cannot create data directory.\n";

        return false;
    }


    // ========================================================
    // CHECK SCRIPT
    // ========================================================

    std::string output;


    if (!executeRemote(
        "test -f " +
        shellQuote(FILEGUARD_SCRIPT),
        &output))
    {
        std::cout
            << "FileGuard script was not found:\n"
            << FILEGUARD_SCRIPT
            << "\n";

        return false;
    }


    // ========================================================
    // PERMISSIONS
    // ========================================================

    if (!setPermissions())
    {
        std::cout
            << "Cannot set FileGuard permissions.\n";

        return false;
    }


    // ========================================================
    // SYSTEMD
    // ========================================================

    if (!serviceExists())
    {
        if (!createSystemdService())
        {
            std::cout
                << "Cannot create systemd service.\n";

            return false;
        }
    }


    // ========================================================
    // RELOAD
    // ========================================================

    if (!reloadSystemd())
    {
        std::cout
            << "systemd reload failed.\n";

        return false;
    }


    // ========================================================
    // ENABLE
    // ========================================================

    if (!enableService())
    {
        std::cout
            << "Cannot enable FileGuard service.\n";

        return false;
    }


    // ========================================================
    // START
    // ========================================================

    if (!startService())
    {
        std::cout
            << "Cannot start FileGuard service.\n";

        return false;
    }


    // ========================================================
    // STATUS
    // ========================================================

    if (!serviceIsActive())
    {
        std::cout
            << "\nFileGuard service is not active.\n"
            << "Check logs for details.\n";

        return false;
    }


    std::cout
        << "\n========================================\n"
        << "FileGuard installed successfully.\n"
        << "Service: "
        << FILEGUARD_SERVICE
        << "\n"
        << "Status: ACTIVE\n"
        << "========================================\n";


    return true;
}


// ============================================================
// START
// ============================================================

bool FileGuard::start()
{
    std::cout
        << "\nStarting FileGuard...\n";


    if (!checkRootOrSudo())
    {
        return false;
    }


    if (!serviceExists())
    {
        std::cout
            << "FileGuard service is not installed.\n";

        return false;
    }


    if (!startService())
    {
        std::cout
            << "Failed to start FileGuard.\n";

        return false;
    }


    if (!serviceIsActive())
    {
        std::cout
            << "FileGuard failed to become active.\n";

        return false;
    }


    std::cout
        << "FileGuard is ACTIVE.\n";


    return true;
}


// ============================================================
// STOP
// ============================================================

bool FileGuard::stop()
{
    std::cout
        << "\nStopping FileGuard...\n";


    if (!checkRootOrSudo())
    {
        return false;
    }


    if (!serviceExists())
    {
        std::cout
            << "FileGuard service is not installed.\n";

        return false;
    }


    if (!stopService())
    {
        std::cout
            << "Failed to stop FileGuard.\n";

        return false;
    }


    std::cout
        << "FileGuard stopped.\n";


    return true;
}


// ============================================================
// DISABLE
// ============================================================

bool FileGuard::disable()
{
    std::cout
        << "\nDisabling FileGuard...\n";


    if (!checkRootOrSudo())
    {
        return false;
    }


    if (!serviceExists())
    {
        std::cout
            << "FileGuard service is not installed.\n";

        return false;
    }


    // Stop first
    stopService();


    if (!disableService())
    {
        std::cout
            << "Failed to disable FileGuard.\n";

        return false;
    }


    std::cout
        << "FileGuard disabled.\n";


    return true;
}


// ============================================================
// STATUS
// ============================================================

bool FileGuard::status()
{
    if (!checkRootOrSudo())
    {
        return false;
    }


    printStatus();


    return serviceIsActive();
}


// ============================================================
// PRINT STATUS
// ============================================================

void FileGuard::printStatus()
{
    std::cout
        << "\n========================================\n"
        << "          FILEGUARD STATUS\n"
        << "========================================\n";


    std::string output;


    if (!serviceExists())
    {
        std::cout
            << "Service: NOT INSTALLED\n"
            << "========================================\n";

        return;
    }


    if (serviceIsActive())
    {
        std::cout
            << "Service: ACTIVE / RUNNING\n";
    }
    else
    {
        std::cout
            << "Service: INACTIVE / STOPPED\n";
    }


    if (executeRemote(
        "systemctl is-enabled " +
        shellQuote(FILEGUARD_SERVICE),
        &output))
    {
        std::cout
            << "Startup: "
            << output;
    }


    std::cout
        << "Script: "
        << FILEGUARD_SCRIPT
        << "\n";


    std::cout
        << "========================================\n";
}


// ============================================================
// LOGS
// ============================================================

bool FileGuard::logs()
{
    if (!checkRootOrSudo())
    {
        return false;
    }


    printLogs();


    return true;
}


// ============================================================
// PRINT LOGS
// ============================================================

void FileGuard::printLogs()
{
    std::cout
        << "\n========================================\n"
        << "          FILEGUARD LOGS\n"
        << "========================================\n";


    std::string output;


    executeRemote(
        "journalctl -u " +
        shellQuote(FILEGUARD_SERVICE) +
        " -n 100 --no-pager",
        &output);


    std::cout
        << output;


    std::cout
        << "========================================\n";
}


// ============================================================
// REBUILD
// ============================================================

bool FileGuard::rebuild()
{
    rebuildBaseline();

    return true;
}


// ============================================================
// REBUILD BASELINE
// ============================================================

void FileGuard::rebuildBaseline()
{
    std::cout
        << "\n========================================\n"
        << "       REBUILD FILEGUARD BASELINE\n"
        << "========================================\n";


    if (!checkRootOrSudo())
    {
        return;
    }


    std::string command =
        "if [ -f " +
        shellQuote(FILEGUARD_SCRIPT) +
        " ]; then "
        "python3 " +
        shellQuote(FILEGUARD_SCRIPT) +
        " --rebuild; "
        "else "
        "echo 'FileGuard script not found'; "
        "exit 1; "
        "fi";


    std::string output;


    if (executeRemote(
        command,
        &output))
    {
        std::cout
            << output
            << "\nBaseline rebuilt successfully.\n";
    }
    else
    {
        std::cout
            << output
            << "\nFailed to rebuild baseline.\n";
    }
}


// ============================================================
// DOWNLOAD UPDATE
// ============================================================

bool FileGuard::downloadUpdate()
{
    std::cout
        << "\n[1/5] Downloading new FileGuard...\n";


    // Remove old temporary file first
    executeRemote(
        "rm -f " +
        shellQuote(FILEGUARD_TEMP_SCRIPT));


    const std::string command =
        "curl -fL "
        "--connect-timeout 15 "
        "--max-time 120 "
        "--retry 2 "
        "-o " +
        shellQuote(FILEGUARD_TEMP_SCRIPT) +
        " " +
        shellQuote(FILEGUARD_UPDATE_URL);


    std::string output;


    if (!executeRemote(
        command,
        &output))
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
            shellQuote(FILEGUARD_TEMP_SCRIPT));


        return false;
    }


    // ========================================================
    // CHECK FILE SIZE
    // ========================================================

    if (!executeRemote(
        "test -s " +
        shellQuote(FILEGUARD_TEMP_SCRIPT),
        &output))
    {
        std::cout
            << "Downloaded file is empty.\n";


        executeRemote(
            "rm -f " +
            shellQuote(FILEGUARD_TEMP_SCRIPT));


        return false;
    }


    std::cout
        << "Download completed.\n";


    return true;
}


// ============================================================
// VERIFY UPDATE
// ============================================================

bool FileGuard::verifyUpdate()
{
    std::cout
        << "[2/5] Checking Python syntax...\n";


    /*
     * We intentionally use ast.parse instead of py_compile.
     *
     * py_compile can create __pycache__ files.
     * FileGuard does not need those files.
     */

    const std::string command =
        "python3 -c " +
        shellQuote(
            "import ast,sys;"
            "p=open(sys.argv[1],encoding='utf-8').read();"
            "ast.parse(p,filename=sys.argv[1]);"
            "print('Python syntax: OK')"
        ) +
        " " +
        shellQuote(FILEGUARD_TEMP_SCRIPT);


    std::string output;


    if (!executeRemote(
        command,
        &output))
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
    // BASIC FILE CHECK
    // ========================================================

    if (!executeRemote(
        "head -n 1 " +
        shellQuote(FILEGUARD_TEMP_SCRIPT) +
        " >/dev/null",
        &output))
    {
        std::cout
            << "Downloaded FileGuard file is invalid.\n";

        return false;
    }


    std::cout
        << "Update verification completed.\n";


    return true;
}


// ============================================================
// BACKUP CURRENT SCRIPT
// ============================================================

bool FileGuard::backupCurrentScript()
{
    std::cout
        << "[3/5] Creating backup of current FileGuard...\n";


    if (!executeRemote(
        "mkdir -p " +
        shellQuote(FILEGUARD_BACKUP_DIR)))
    {
        std::cout
            << "Cannot create backup directory.\n";

        return false;
    }


    if (!executeRemote(
        "test -f " +
        shellQuote(FILEGUARD_SCRIPT)))
    {
        std::cout
            << "Current FileGuard script not found.\n";

        return false;
    }


    /*
     * Only one backup is maintained.
     *
     * The old backup is removed immediately before creating
     * the new backup. This prevents accumulation of old files.
     */

    if (!executeRemote(
        "rm -f " +
        shellQuote(FILEGUARD_BACKUP_SCRIPT)))
    {
        std::cout
            << "Cannot remove old FileGuard backup.\n";

        return false;
    }


    if (!executeRemote(
        "cp -p " +
        shellQuote(FILEGUARD_SCRIPT) +
        " " +
        shellQuote(FILEGUARD_BACKUP_SCRIPT)))
    {
        std::cout
            << "Cannot create FileGuard backup.\n";

        return false;
    }


    executeRemote(
        "chown root:root " +
        shellQuote(FILEGUARD_BACKUP_SCRIPT));


    executeRemote(
        "chmod 700 " +
        shellQuote(FILEGUARD_BACKUP_SCRIPT));


    std::cout
        << "Backup created:\n"
        << FILEGUARD_BACKUP_SCRIPT
        << "\n";


    return true;
}


// ============================================================
// INSTALL UPDATED SCRIPT
// ============================================================

bool FileGuard::installUpdatedScript()
{
    std::cout
        << "[4/5] Installing new FileGuard...\n";


    /*
     * mv is used here so that the final replacement is atomic
     * on the same filesystem.
     */

    if (!executeRemote(
        "mv -f " +
        shellQuote(FILEGUARD_TEMP_SCRIPT) +
        " " +
        shellQuote(FILEGUARD_SCRIPT)))
    {
        std::cout
            << "Cannot replace FileGuard script.\n";

        return false;
    }


    if (!executeRemote(
        "chown root:root " +
        shellQuote(FILEGUARD_SCRIPT)))
    {
        std::cout
            << "Cannot set owner of updated script.\n";

        return false;
    }


    if (!executeRemote(
        "chmod 700 " +
        shellQuote(FILEGUARD_SCRIPT)))
    {
        std::cout
            << "Cannot set permissions of updated script.\n";

        return false;
    }


    return true;
}


// ============================================================
// ROLLBACK UPDATE
// ============================================================

bool FileGuard::rollbackUpdate()
{
    std::cout
        << "\n========================================\n"
        << "        ROLLING BACK FILEGUARD\n"
        << "========================================\n";


    if (!executeRemote(
        "test -f " +
        shellQuote(FILEGUARD_BACKUP_SCRIPT)))
    {
        std::cout
            << "Backup file not found.\n";

        return false;
    }


    if (!executeRemote(
        "cp -p " +
        shellQuote(FILEGUARD_BACKUP_SCRIPT) +
        " " +
        shellQuote(FILEGUARD_SCRIPT)))
    {
        std::cout
            << "Rollback copy failed.\n";

        return false;
    }


    executeRemote(
        "chown root:root " +
        shellQuote(FILEGUARD_SCRIPT));


    executeRemote(
        "chmod 700 " +
        shellQuote(FILEGUARD_SCRIPT));


    executeRemote(
        "rm -f " +
        shellQuote(FILEGUARD_TEMP_SCRIPT));


    // ========================================================
    // RESTART OLD VERSION
    // ========================================================

    if (!executeRemote(
        "systemctl restart " +
        shellQuote(FILEGUARD_SERVICE)))
    {
        std::cout
            << "Rollback completed, but service restart failed.\n";

        return false;
    }


    // ========================================================
    // CHECK OLD VERSION
    // ========================================================

    if (serviceIsActive())
    {
        std::cout
            << "Rollback successful.\n"
            << "Previous FileGuard version is ACTIVE.\n";

        return true;
    }


    std::cout
        << "Rollback completed, but FileGuard is not active.\n";


    return false;
}


// ============================================================
// UPDATE
// ============================================================

bool FileGuard::update()
{
    std::cout
        << "\n========================================\n"
        << "          UPDATE FILEGUARD\n"
        << "========================================\n\n";


    // ========================================================
    // ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        return false;
    }


    // ========================================================
    // SERVICE CHECK
    // ========================================================

    if (!serviceExists())
    {
        std::cout
            << "FileGuard service is not installed.\n"
            << "Install FileGuard first.\n";

        return false;
    }


    // ========================================================
    // CURRENT SCRIPT CHECK
    // ========================================================

    if (!executeRemote(
        "test -f " +
        shellQuote(FILEGUARD_SCRIPT)))
    {
        std::cout
            << "Current FileGuard script was not found.\n";

        return false;
    }


    // ========================================================
    // CURL
    // ========================================================

    if (!commandExists("curl"))
    {
        std::cout
            << "curl is not installed.\n";

        std::cout
            << "Installing curl...\n";


        std::string output;


        if (!executeRemote(
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y curl",
            &output))
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
            << "Current FileGuard was not changed.\n";


        executeRemote(
            "rm -f " +
            shellQuote(FILEGUARD_TEMP_SCRIPT));


        return false;
    }


    // ========================================================
    // BACKUP
    // ========================================================

    if (!backupCurrentScript())
    {
        executeRemote(
            "rm -f " +
            shellQuote(FILEGUARD_TEMP_SCRIPT));

        return false;
    }


    // ========================================================
    // INSTALL NEW FILE
    // ========================================================

    if (!installUpdatedScript())
    {
        std::cout
            << "\nNew FileGuard was not installed.\n";


        executeRemote(
            "rm -f " +
            shellQuote(FILEGUARD_TEMP_SCRIPT));


        return false;
    }


    // ========================================================
    // RESTART SERVICE
    // ========================================================

    std::cout
        << "[5/5] Restarting FileGuard service...\n";


    if (!executeRemote(
        "systemctl restart " +
        shellQuote(FILEGUARD_SERVICE)))
    {
        std::cout
            << "Failed to restart FileGuard.\n";


        rollbackUpdate();


        return false;
    }


    // ========================================================
    // WAIT A LITTLE
    // ========================================================

    executeRemote(
        "sleep 1");


    // ========================================================
    // ACTIVE CHECK
    // ========================================================

    if (!serviceIsActive())
    {
        std::cout
            << "\n========================================\n"
            << "   NEW FILEGUARD FAILED TO START\n"
            << "========================================\n";


        std::cout
            << "Automatic rollback started...\n";


        rollbackUpdate();


        return false;
    }


    // ========================================================
    // CLEAN OLD FILES
    // ========================================================

    /*
     * IMPORTANT:
     *
     * Cleanup is performed ONLY after the new FileGuard
     * has successfully started and systemd reports ACTIVE.
     *
     * The previous working version remains as:
     *
     * /opt/serverguard/backups/fileguard/file_guard.py
     *
     * All other files inside the FileGuard backup directory
     * are removed.
     */

    std::cout
        << "\nCleaning old FileGuard update files...\n";


    std::string cleanupOutput;


    const std::string cleanupCommand =
        "if [ -d " +
        shellQuote(FILEGUARD_BACKUP_DIR) +
        " ]; then "
        "find " +
        shellQuote(FILEGUARD_BACKUP_DIR) +
        " -mindepth 1 "
        "! -path " +
        shellQuote(FILEGUARD_BACKUP_SCRIPT) +
        " -delete; "
        "fi";


    if (!executeRemote(
        cleanupCommand,
        &cleanupOutput))
    {
        /*
         * Cleanup failure does NOT invalidate the update.
         *
         * The new FileGuard is already running successfully.
         */

        std::cout
            << "Warning: old backup cleanup failed.\n";

        if (!cleanupOutput.empty())
        {
            std::cout
                << cleanupOutput
                << "\n";
        }
    }
    else
    {
        std::cout
            << "Old FileGuard backup files cleaned.\n";
    }


    // ========================================================
    // REMOVE TEMPORARY UPDATE FILE
    // ========================================================

    if (!executeRemote(
        "rm -f " +
        shellQuote(FILEGUARD_TEMP_SCRIPT)))
    {
        std::cout
            << "Warning: temporary update file cleanup failed.\n";
    }
    else
    {
        std::cout
            << "Temporary update file removed.\n";
    }


    // ========================================================
    // SUCCESS
    // ========================================================

    std::cout
        << "\n========================================\n"
        << "      FILEGUARD UPDATE SUCCESSFUL\n"
        << "========================================\n"
        << "Source:\n"
        << FILEGUARD_UPDATE_URL
        << "\n\n"
        << "Service: ACTIVE\n"
        << "Current version:\n"
        << FILEGUARD_SCRIPT
        << "\n"
        << "Previous version:\n"
        << FILEGUARD_BACKUP_SCRIPT
        << "\n"
        << "Old update files: CLEANED\n"
        << "========================================\n";


    return true;
}


// ============================================================
// MENU
// ============================================================

void FileGuard::menu()
{
    while (true)
    {
        std::cout
            << "\n"
            << "========================================\n"
            << "          SERVERGUARD FILEGUARD\n"
            << "========================================\n"
            << "1. Install / enable FileGuard\n"
            << "2. Start FileGuard\n"
            << "3. Stop FileGuard\n"
            << "4. Disable automatic startup\n"
            << "5. Check status\n"
            << "6. Show logs\n"
            << "7. Rebuild baseline\n"
            << "8. Update FileGuard\n"
            << "0. Back\n"
            << "========================================\n"
            << "Select: ";


        int choice;


        std::cin
            >> choice;


        if (std::cin.fail())
        {
            std::cin.clear();


            std::cin.ignore(
                10000,
                '\n');


            std::cout
                << "Invalid input.\n";


            continue;
        }


        switch (choice)
        {
        case 1:
            install();
            break;


        case 2:
            start();
            break;


        case 3:
            stop();
            break;


        case 4:
            disable();
            break;


        case 5:
            status();
            break;


        case 6:
            logs();
            break;


        case 7:
            rebuild();
            break;


        case 8:
        {
            std::cout
                << "\nUpdate FileGuard from GitHub?\n"
                << "This will download the new file, "
                << "backup the current version and "
                << "restart the service.\n"
                << "Continue? [y/N]: ";


            char answer;


            std::cin
                >> answer;


            if (answer == 'y' ||
                answer == 'Y')
            {
                update();
            }
            else
            {
                std::cout
                    << "Update cancelled.\n";
            }


            break;
        }


        case 0:
            return;


        default:
            std::cout
                << "Unknown option.\n";

            break;
        }
    }
}