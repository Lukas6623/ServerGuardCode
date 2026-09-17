#include "TelegramBot.h"

#include <iostream>
#include <string>
#include <sstream>
#include <random>
#include <ctime>
#include <thread>
#include <chrono>


// ============================================================
// SERVER PATHS
// ============================================================

static const std::string TELEGRAM_DIR =
"/opt/serverguard/telegram";

static const std::string TELEGRAM_SCRIPT =
"/opt/serverguard/telegram/telegram_bot.py";

static const std::string TELEGRAM_CONFIG =
"/opt/serverguard/telegram/telegram.conf";

static const std::string TELEGRAM_VERIFICATION =
"/opt/serverguard/telegram/verification.json";

static const std::string TELEGRAM_OWNER =
"/opt/serverguard/telegram/owner.json";

static const std::string TELEGRAM_QUEUE =
"/opt/serverguard/telegram/queue";

static const std::string TELEGRAM_VENV =
"/opt/serverguard/telegram/venv";

static const std::string TELEGRAM_SERVICE =
"serverguard-telegram.service";

static const std::string TELEGRAM_SERVICE_PATH =
"/etc/systemd/system/serverguard-telegram.service";


// ============================================================
// GITHUB
// ============================================================
//
// IMPORTANT:
// The Telegram bot is now stored in a separate repository.
//
// Repository:
// https://github.com/Lukas6623/ServerGuardTelegram
//
// GitHub archive contains the COMPLETE repository.
// It may contain:
//   telegram_bot.py
//   requirements.txt
//   handlers/
//   modules/
//   utils/
//   config/
//   other .py files
//   other directories
//
// Everything from the repository is copied to TELEGRAM_DIR.
//
// Runtime data is NOT replaced:
//   telegram.conf
//   verification.json
//   owner.json
//   queue/
//   venv/
// ============================================================

static const std::string GITHUB_TELEGRAM_REPOSITORY_ZIP =
"https://github.com/"
"Lukas6623/ServerGuardTelegram/"
"archive/refs/heads/main.zip";


// ============================================================
// UPDATE / TEMP
// ============================================================

static const std::string TELEGRAM_UPDATE_DIR =
"/opt/serverguard/telegram/.repository_update";

static const std::string TELEGRAM_UPDATE_ZIP =
"/opt/serverguard/telegram/.repository_update.zip";


// ============================================================
// BACKUP
// ============================================================
//
// Backup is OUTSIDE the active Telegram directory.
//
// This is important because the active directory is replaced
// during an update.
//
// Runtime files are not backed up here because they are preserved
// directly in the active directory.
// ============================================================

static const std::string TELEGRAM_CODE_BACKUP =
"/opt/serverguard/telegram_backup";


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
// BASE64
// ============================================================

static std::string base64Encode(
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
        val = (val << 8) + c;
        valb += 8;

        while (valb >= 0)
        {
            output.push_back(
                table[(val >> valb) & 0x3F]
            );

            valb -= 6;
        }
    }

    if (valb > -6)
    {
        output.push_back(
            table[
                ((val << 8) >>
                    (valb + 8)) & 0x3F
            ]
        );
    }

    while (output.size() % 4)
    {
        output.push_back('=');
    }

    return output;
}


// ============================================================
// TRIM
// ============================================================

static std::string trim(
    const std::string& value
)
{
    std::size_t start = 0;

    while (
        start < value.size() &&
        (
            value[start] == ' ' ||
            value[start] == '\n' ||
            value[start] == '\r' ||
            value[start] == '\t'
            )
        )
    {
        ++start;
    }

    std::size_t end = value.size();

    while (
        end > start &&
        (
            value[end - 1] == ' ' ||
            value[end - 1] == '\n' ||
            value[end - 1] == '\r' ||
            value[end - 1] == '\t'
            )
        )
    {
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

TelegramBot::TelegramBot(
    LIBSSH2_SESSION* sshSession,
    const std::string& password
)
{
    session = sshSession;

    sudoPassword = password;

    sudoRequired = false;

    sudoAuthenticated = false;
}


// ============================================================
// EXECUTE REMOTE COMMAND
// ============================================================

bool TelegramBot::executeRemote(
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
        output =
            "SSH session is invalid.";

        return false;
    }

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
                output =
                    "Cannot authenticate sudo.";

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
        output =
            "Cannot open SSH channel.";

        return false;
    }


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
        output =
            "Cannot execute remote command.";

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


// ============================================================
// AUTHENTICATE SUDO
// ============================================================

bool TelegramBot::authenticateSudo()
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
            << "Cannot open sudo channel.\n";

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
        libssh2_channel_free(channel);

        return false;
    }


    std::string password =
        sudoPassword + "\n";

    size_t totalWritten = 0;


    while (
        totalWritten <
        password.size()
        )
    {
        int written =
            static_cast<int>(
                libssh2_channel_write(
                    channel,
                    password.c_str() +
                    totalWritten,
                    password.size() -
                    totalWritten
                )
                );

        if (written < 0)
        {
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


    libssh2_channel_send_eof(
        channel
    );


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

        if (rc ==
            LIBSSH2_ERROR_EAGAIN)
        {
            continue;
        }

        break;
    }


    libssh2_channel_wait_eof(
        channel
    );

    libssh2_channel_wait_closed(
        channel
    );


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

bool TelegramBot::commandExists(
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

bool TelegramBot::checkRootOrSudo()
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


    std::stringstream stream(output);

    int uid = -1;

    stream >> uid;


    if (uid == 0)
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
// CREATE DIRECTORIES
// ============================================================

bool TelegramBot::createDirectories()
{
    std::cout
        << "Creating Telegram directories...\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "mkdir -p " +
        shellQuote(TELEGRAM_DIR) +
        " " +
        shellQuote(TELEGRAM_QUEUE);


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create Telegram directories.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "Telegram directories created.\n";


    return true;
}


// ============================================================
// INSTALL PYTHON DEPENDENCIES
// ============================================================

bool TelegramBot::installPythonDependencies()
{
    std::cout
        << "\nChecking Python environment...\n";


    // ========================================================
    // PYTHON3
    // ========================================================

    if (!commandExists("python3"))
    {
        std::cout
            << "Python3 not found.\n";

        std::cout
            << "Installing Python3...\n";


        std::string output;

        int exitCode = -1;


        if (!executeRemote(
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y python3",
            output,
            exitCode,
            true
        ))
        {
            std::cout
                << "Failed to install Python3.\n";

            if (!output.empty())
                std::cout << output << "\n";

            return false;
        }
    }


    // ========================================================
    // APT
    // ========================================================

    if (!commandExists("apt-get"))
    {
        std::cout
            << "apt-get not found.\n";

        return false;
    }


    // ========================================================
    // VENV / PIP / CURL / UNZIP
    // ========================================================

    std::cout
        << "Checking Python packages...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "apt-get update && "
        "DEBIAN_FRONTEND=noninteractive "
        "apt-get install -y "
        "python3-venv "
        "python3-pip "
        "curl "
        "unzip",
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Failed to install Python requirements.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }


    // ========================================================
    // CREATE VENV ONLY IF MISSING
    // ========================================================

    std::cout
        << "Checking Telegram virtual environment...\n";


    std::string venvPython =
        TELEGRAM_VENV +
        "/bin/python";


    bool venvExists = executeRemote(
        "test -x " +
        shellQuote(venvPython),
        output,
        exitCode,
        false
    );


    if (!venvExists)
    {
        std::cout
            << "Virtual environment not found.\n";

        std::cout
            << "Creating virtual environment...\n";


        if (!executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_VENV) +
            " && "
            "python3 -m venv " +
            shellQuote(TELEGRAM_VENV),
            output,
            exitCode,
            true
        ))
        {
            std::cout
                << "Failed to create virtual environment.\n";

            if (!output.empty())
                std::cout << output << "\n";

            return false;
        }


        std::cout
            << "Virtual environment created.\n";
    }
    else
    {
        std::cout
            << "Virtual environment already exists.\n";
    }


    // ========================================================
    // CHECK PYTHON
    // ========================================================

    output.clear();

    exitCode = -1;


    if (!executeRemote(
        shellQuote(venvPython) +
        " --version",
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Virtual environment Python is not working.\n";

        return false;
    }


    if (!output.empty())
    {
        std::cout
            << output;
    }


    // ========================================================
    // CHECK AIOGRAM
    // ========================================================

    std::cout
        << "Checking aiogram...\n";


    output.clear();

    exitCode = -1;


    bool aiogramInstalled =
        executeRemote(
            shellQuote(venvPython) +
            " -c \"import aiogram\"",
            output,
            exitCode,
            false
        );


    if (!aiogramInstalled)
    {
        std::cout
            << "aiogram is not installed.\n";

        std::cout
            << "Installing aiogram...\n";


        output.clear();

        exitCode = -1;


        if (!executeRemote(
            shellQuote(venvPython) +
            " -m pip install aiogram",
            output,
            exitCode,
            true
        ))
        {
            std::cout
                << "Failed to install aiogram.\n";

            if (!output.empty())
                std::cout << output << "\n";

            return false;
        }


        std::cout
            << "aiogram installed.\n";
    }
    else
    {
        std::cout
            << "aiogram is already installed.\n";
    }


    return true;
}


// ============================================================
// CHECK SCRIPT
// ============================================================

bool TelegramBot::checkScript()
{
    std::string output;

    int exitCode = -1;


    executeRemote(
        "test -f " +
        shellQuote(TELEGRAM_SCRIPT),
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


// ============================================================
// ENSURE UNZIP
// ============================================================

bool TelegramBot::ensureUnzip()
{
    if (commandExists("unzip"))
    {
        return true;
    }


    std::cout
        << "unzip is not installed.\n";

    std::cout
        << "Installing unzip...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "apt-get update && "
        "DEBIAN_FRONTEND=noninteractive "
        "apt-get install -y unzip",
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot install unzip.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    return commandExists("unzip");
}


// ============================================================
// DOWNLOAD REPOSITORY ARCHIVE
// ============================================================

bool TelegramBot::downloadRepositoryArchive(
    const std::string& archivePath
)
{
    std::cout
        << "\nDownloading Telegram bot repository...\n";


    std::cout
        << "Repository:\n"
        << GITHUB_TELEGRAM_REPOSITORY_ZIP
        << "\n\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "rm -f " +
        shellQuote(archivePath) +
        " && "
        "curl -fL --silent --show-error "
        "--connect-timeout 15 "
        "--max-time 180 "
        "--retry 3 "
        "--retry-delay 2 "
        "-o " +
        shellQuote(archivePath) +
        " " +
        shellQuote(
            GITHUB_TELEGRAM_REPOSITORY_ZIP
        );


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Repository download failed.\n";


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
        shellQuote(archivePath),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Downloaded repository archive is empty.\n";

        return false;
    }


    std::cout
        << "Repository archive downloaded successfully.\n";


    return true;
}


// ============================================================
// EXTRACT REPOSITORY
// ============================================================

bool TelegramBot::extractRepository(
    const std::string& archivePath,
    const std::string& extractDirectory,
    std::string& repositoryRoot
)
{
    repositoryRoot.clear();

    std::cout
        << "\nExtracting Telegram bot repository...\n";

    std::string output;
    int exitCode = -1;

    // ========================================================
    // CLEAN + CREATE DIRECTORY
    // ========================================================

    std::string command =
        "rm -rf " +
        shellQuote(extractDirectory) +
        " && "
        "mkdir -p " +
        shellQuote(extractDirectory) +
        " && "
        "unzip -q " +
        shellQuote(archivePath) +
        " -d " +
        shellQuote(extractDirectory);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot extract Telegram repository.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    // ========================================================
    // FIND telegram_bot.py ANYWHERE IN EXTRACTED REPOSITORY
    //
    // The GitHub repository sometimes ships the bot code
    // packed inside a NESTED .zip file instead of raw files,
    // e.g.:
    //   ServerGuardTelegram-main/ServerGuardTelegram.zip
    //
    // If telegram_bot.py is not found directly, look for any
    // .zip files inside the extracted tree and unpack them in
    // place, then search again. Repeat until the script is
    // found or there is nothing left to unpack.
    // ========================================================

    std::cout
        << "Searching extracted repository for telegram_bot.py...\n";

    std::string mainScript;

    const int MAX_NESTED_UNZIP_ITERATIONS = 5;

    for (
        int iteration = 0;
        iteration < MAX_NESTED_UNZIP_ITERATIONS;
        ++iteration
        )
    {
        output.clear();
        exitCode = -1;

        command =
            "find " +
            shellQuote(extractDirectory) +
            " -type f -name 'telegram_bot.py' "
            "-print -quit";

        if (!executeRemote(
            command,
            output,
            exitCode,
            false
        ))
        {
            std::cout
                << "Cannot search extracted Telegram repository.\n";

            return false;
        }

        mainScript = trim(output);

        if (!mainScript.empty())
        {
            break;
        }

        // Not found yet - look for nested zip archives.

        output.clear();
        exitCode = -1;

        command =
            "find " +
            shellQuote(extractDirectory) +
            " -type f -name '*.zip' "
            "-print";

        executeRemote(
            command,
            output,
            exitCode,
            false
        );

        std::string nestedZips = trim(output);

        if (nestedZips.empty())
        {
            // Nothing left to unpack.
            break;
        }

        std::cout
            << "Nested archive(s) found inside repository, "
            "extracting...\n";

        std::istringstream zipStream(nestedZips);
        std::string zipPath;

        while (std::getline(zipStream, zipPath))
        {
            zipPath = trim(zipPath);

            if (zipPath.empty())
            {
                continue;
            }

            std::cout
                << "Extracting nested archive:\n"
                << zipPath
                << "\n";

            std::string nestedExtractDir =
                zipPath +
                ".__extracted";

            std::string extractCommand =
                "unzip -q -o " +
                shellQuote(zipPath) +
                " -d " +
                shellQuote(nestedExtractDir) +
                " && rm -f " +
                shellQuote(zipPath);

            std::string extractOutput;
            int extractExitCode = -1;

            if (!executeRemote(
                extractCommand,
                extractOutput,
                extractExitCode,
                true
            ))
            {
                std::cout
                    << "Cannot extract nested archive:\n"
                    << zipPath
                    << "\n";

                if (!extractOutput.empty())
                {
                    std::cout
                        << extractOutput
                        << "\n";
                }

                // Keep trying other archives / iterations.
            }
        }
    }

    // ========================================================
    // SCRIPT NOT FOUND
    // ========================================================

    if (mainScript.empty())
    {
        std::cout
            << "ERROR: telegram_bot.py was not found "
            "anywhere in extracted repository "
            "(including nested archives).\n";

        std::cout
            << "Extracted directory:\n"
            << extractDirectory
            << "\n";

        // Show extracted files to make debugging easier.

        output.clear();
        exitCode = -1;

        executeRemote(
            "find " +
            shellQuote(extractDirectory) +
            " -maxdepth 6 -print",
            output,
            exitCode,
            false
        );

        if (!output.empty())
        {
            std::cout
                << "\nExtracted repository contents:\n"
                << output
                << "\n";
        }

        return false;
    }

    // ========================================================
    // DETERMINE DIRECTORY CONTAINING telegram_bot.py
    // ========================================================

    output.clear();
    exitCode = -1;

    command =
        "dirname " +
        shellQuote(mainScript);

    if (!executeRemote(
        command,
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Cannot determine Telegram repository root.\n";

        return false;
    }

    repositoryRoot = trim(output);

    if (repositoryRoot.empty())
    {
        std::cout
            << "Repository root is empty.\n";

        return false;
    }

    // ========================================================
    // SHOW RESULT
    // ========================================================

    std::cout
        << "Telegram bot entry point found:\n"
        << mainScript
        << "\n";

    std::cout
        << "Repository root:\n"
        << repositoryRoot
        << "\n";

    return true;
}

// ============================================================
// VALIDATE REPOSITORY
// ============================================================

bool TelegramBot::validateRepository(
    const std::string& repositoryRoot
)
{
    std::cout
        << "\nValidating Telegram repository...\n";

    // ========================================================
    // MAIN SCRIPT
    // ========================================================

    std::string mainScript =
        repositoryRoot +
        "/telegram_bot.py";

    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "test -f " +
        shellQuote(mainScript),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "ERROR: telegram_bot.py was not found.\n";

        std::cout
            << "Expected:\n"
            << mainScript
            << "\n";

        // Extra diagnostic search.

        output.clear();
        exitCode = -1;

        executeRemote(
            "find " +
            shellQuote(repositoryRoot) +
            " -type f -name 'telegram_bot.py' "
            "-print",
            output,
            exitCode,
            false
        );

        if (!output.empty())
        {
            std::cout
                << "\nFound telegram_bot.py files:\n"
                << output
                << "\n";
        }

        return false;
    }

    std::cout
        << "Main Telegram bot file found:\n"
        << mainScript
        << "\n";

    // ========================================================
    // CHECK REPOSITORY CONTENT
    // ========================================================

    std::cout
        << "\nChecking repository contents...\n";

    output.clear();
    exitCode = -1;

    executeRemote(
        "find " +
        shellQuote(repositoryRoot) +
        " -maxdepth 2 -print",
        output,
        exitCode,
        false
    );

    if (!output.empty())
    {
        std::cout
            << output
            << "\n";
    }

    // ========================================================
    // PYTHON SYNTAX
    // ========================================================

    std::cout
        << "Checking Python syntax for repository...\n";

    std::string python =
        TELEGRAM_VENV +
        "/bin/python";

    output.clear();
    exitCode = -1;

    std::string command =
        shellQuote(python) +
        " -m compileall -q " +
        shellQuote(repositoryRoot);

    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Repository Python syntax validation FAILED.\n";

        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }

        return false;
    }

    std::cout
        << "All Python files passed syntax validation.\n";

    // ========================================================
    // REMOVE PYTHON CACHE
    // ========================================================

    output.clear();
    exitCode = -1;

    executeRemote(
        "find " +
        shellQuote(repositoryRoot) +
        " -type d -name __pycache__ "
        "-prune -exec rm -rf {} +",
        output,
        exitCode,
        true
    );

    std::cout
        << "Repository validation successful.\n";

    return true;
}

// ============================================================
// SET REPOSITORY PERMISSIONS
// ============================================================

bool TelegramBot::setRepositoryPermissions()
{
    std::cout
        << "\nConfiguring Telegram repository permissions...\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "find " +
        shellQuote(TELEGRAM_DIR) +
        " -type d "
        "! -path " +
        shellQuote(TELEGRAM_QUEUE) +
        " -exec chmod 755 {} +; "
        "find " +
        shellQuote(TELEGRAM_DIR) +
        " -type f "
        "! -path " +
        shellQuote(TELEGRAM_CONFIG) +
        " "
        "! -path " +
        shellQuote(TELEGRAM_VERIFICATION) +
        " "
        "! -path " +
        shellQuote(TELEGRAM_OWNER) +
        " -exec chmod 644 {} +; "
        "chmod 755 " +
        shellQuote(TELEGRAM_SCRIPT) +
        "; "
        "chown -R root:root " +
        shellQuote(TELEGRAM_DIR);


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot configure repository permissions.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    // ========================================================
    // RESTORE PRIVATE RUNTIME PERMISSIONS
    // ========================================================

    command =
        "chmod 600 " +
        shellQuote(TELEGRAM_CONFIG) +
        " 2>/dev/null || true; "
        "chmod 600 " +
        shellQuote(TELEGRAM_VERIFICATION) +
        " 2>/dev/null || true; "
        "chmod 600 " +
        shellQuote(TELEGRAM_OWNER) +
        " 2>/dev/null || true; "
        "chown -R root:root " +
        shellQuote(TELEGRAM_QUEUE) +
        " 2>/dev/null || true; "
        "chown -R root:root " +
        shellQuote(TELEGRAM_VENV) +
        " 2>/dev/null || true";


    executeRemote(
        command,
        output,
        exitCode,
        true
    );


    std::cout
        << "Repository permissions configured.\n";


    return true;
}


// ============================================================
// INSTALL REPOSITORY FILES
// ============================================================

bool TelegramBot::installRepositoryFiles(
    const std::string& repositoryRoot
)
{
    std::cout
        << "\nInstalling Telegram repository files...\n";


    std::string output;

    int exitCode = -1;


    // ========================================================
    // COPY EVERYTHING FROM REPOSITORY
    //
    // Runtime files are explicitly excluded.
    // ========================================================

    std::string command =
        "find " +
        shellQuote(repositoryRoot) +
        " -mindepth 1 -maxdepth 1 "
        "! -name telegram.conf "
        "! -name verification.json "
        "! -name owner.json "
        "! -name queue "
        "! -name venv "
        "-exec cp -a {} " +
        shellQuote(TELEGRAM_DIR) +
        "/ \\;";


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot install repository files.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    if (!setRepositoryPermissions())
    {
        return false;
    }


    std::cout
        << "Telegram repository installed successfully.\n";


    return true;
}


// ============================================================
// CHECK TELEGRAM BOT / DOWNLOAD BOT
// ============================================================
//
// This method is intentionally still named downloadBot()
// because it is part of the original TelegramBot interface.
//
// Previously it only checked the existing telegram_bot.py.
//
// Now it downloads and installs the COMPLETE GitHub repository.
// ============================================================

bool TelegramBot::downloadBot()
{
    std::cout
        << "\nDownloading Telegram bot repository...\n";


    if (!ensureUnzip())
    {
        return false;
    }


    // ========================================================
    // CLEAN TEMP
    // ========================================================

    std::string output;

    int exitCode = -1;


    executeRemote(
        "rm -rf " +
        shellQuote(TELEGRAM_UPDATE_DIR) +
        " " +
        shellQuote(TELEGRAM_UPDATE_ZIP),
        output,
        exitCode,
        true
    );


    // ========================================================
    // DOWNLOAD ZIP
    // ========================================================

    if (!downloadRepositoryArchive(
        TELEGRAM_UPDATE_ZIP
    ))
    {
        return false;
    }


    // ========================================================
    // EXTRACT
    // ========================================================

    std::string repositoryRoot;


    if (!extractRepository(
        TELEGRAM_UPDATE_ZIP,
        TELEGRAM_UPDATE_DIR,
        repositoryRoot
    ))
    {
        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );

        return false;
    }


    // ========================================================
    // VALIDATE
    // ========================================================

    if (!validateRepository(
        repositoryRoot
    ))
    {
        std::cout
            << "\nTelegram repository validation failed.\n";

        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );

        return false;
    }


    // ========================================================
    // INSTALL
    // ========================================================

    if (!installRepositoryFiles(
        repositoryRoot
    ))
    {
        std::cout
            << "\nFailed to install Telegram repository.\n";

        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );

        return false;
    }


    // ========================================================
    // CLEAN TEMP
    // ========================================================

    executeRemote(
        "rm -rf " +
        shellQuote(TELEGRAM_UPDATE_DIR) +
        " " +
        shellQuote(TELEGRAM_UPDATE_ZIP),
        output,
        exitCode,
        true
    );


    // ========================================================
    // FINAL CHECK
    // ========================================================

    if (!checkScript())
    {
        std::cout
            << "Telegram bot script is missing after installation.\n";

        return false;
    }


    if (!checkPythonSyntax(
        TELEGRAM_SCRIPT
    ))
    {
        std::cout
            << "Telegram bot Python syntax check failed.\n";

        return false;
    }


    std::cout
        << "\nTelegram bot repository installed successfully.\n";


    return true;
}


// ============================================================
// CONFIG EXISTS
// ============================================================

bool TelegramBot::configExists()
{
    std::string output;

    int exitCode = -1;


    executeRemote(
        "test -s " +
        shellQuote(TELEGRAM_CONFIG),
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


// ============================================================
// READ BOT TOKEN
// ============================================================

std::string TelegramBot::readBotToken()
{
    std::string token;


    std::cout
        << "\n";

    std::cout
        << "Telegram Bot Token\n";

    std::cout
        << "------------------\n";

    std::cout
        << "Enter token: ";


    std::getline(
        std::cin >> std::ws,
        token
    );


    return token;
}


// ============================================================
// CREATE CONFIG
// ============================================================

bool TelegramBot::createConfig()
{
    if (configExists())
    {
        std::cout
            << "\nTelegram configuration already exists.\n";

        std::cout
            << "Existing bot token will be preserved.\n";

        return true;
    }


    std::cout
        << "\nConfiguring Telegram bot...\n";


    std::string token =
        readBotToken();


    if (token.empty())
    {
        std::cout
            << "Bot token cannot be empty.\n";

        return false;
    }


    // ========================================================
    // BASIC TOKEN VALIDATION
    // ========================================================

    std::size_t colon =
        token.find(':');


    if (
        colon == std::string::npos ||
        colon == 0 ||
        colon == token.size() - 1
        )
    {
        std::cout
            << "Telegram token format looks invalid.\n";

        std::cout
            << "Expected format:\n";

        std::cout
            << "123456789:AAxxxxxxxx...\n";

        return false;
    }


    std::string config =
        "BOT_TOKEN=" +
        token +
        "\n";


    std::string encoded =
        base64Encode(config);


    std::string command =
        "echo " +
        shellQuote(encoded) +
        " | base64 -d > " +
        shellQuote(TELEGRAM_CONFIG) +
        " && "
        "chmod 600 " +
        shellQuote(TELEGRAM_CONFIG) +
        " && "
        "chown root:root " +
        shellQuote(TELEGRAM_CONFIG);


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create Telegram configuration.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "Telegram configuration created.\n";


    return true;
}


// ============================================================
// CREATE SYSTEMD SERVICE
// ============================================================

bool TelegramBot::createSystemdService()
{
    std::cout
        << "\nCreating Telegram systemd service...\n";


    std::string service;


    service +=
        "[Unit]\n";

    service +=
        "Description=ServerGuard Telegram Security Bot\n";

    service +=
        "After=network-online.target\n";

    service +=
        "Wants=network-online.target\n\n";


    service +=
        "[Service]\n";

    service +=
        "Type=simple\n";

    service +=
        "ExecStart=" +
        TELEGRAM_VENV +
        "/bin/python " +
        TELEGRAM_SCRIPT +
        "\n";

    service +=
        "WorkingDirectory=" +
        TELEGRAM_DIR +
        "\n";

    service +=
        "User=root\n";

    service +=
        "Group=root\n";

    service +=
        "Restart=always\n";

    service +=
        "RestartSec=5\n";

    service +=
        "Environment=PYTHONUNBUFFERED=1\n";

    service +=
        "NoNewPrivileges=false\n\n";


    service +=
        "[Install]\n";

    service +=
        "WantedBy=multi-user.target\n";


    // ========================================================
    // BASE64
    // ========================================================

    std::string encoded =
        base64Encode(service);


    std::string command =
        "echo " +
        shellQuote(encoded) +
        " | base64 -d > " +
        shellQuote(
            TELEGRAM_SERVICE_PATH
        );


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create Telegram systemd service.\n";

        return false;
    }


    // ========================================================
    // PERMISSIONS
    // ========================================================

    command =
        "chmod 644 " +
        shellQuote(
            TELEGRAM_SERVICE_PATH
        ) +
        " && "
        "chown root:root " +
        shellQuote(
            TELEGRAM_SERVICE_PATH
        );


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
            << "Cannot configure service permissions.\n";

        return false;
    }


    std::cout
        << "Telegram systemd service created.\n";


    return true;
}


// ============================================================
// RELOAD SYSTEMD
// ============================================================

bool TelegramBot::reloadSystemd()
{
    std::cout
        << "\nReloading systemd...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "systemctl daemon-reload",
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "systemd reload failed.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "systemd reloaded.\n";


    return true;
}


// ============================================================
// ENABLE
// ============================================================

bool TelegramBot::enableService()
{
    std::cout
        << "\nEnabling Telegram automatic startup...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "systemctl enable " +
        TELEGRAM_SERVICE,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Failed to enable Telegram service.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "Telegram automatic startup enabled.\n";


    return true;
}


// ============================================================
// START
// ============================================================

bool TelegramBot::startService()
{
    std::cout
        << "\nStarting Telegram bot...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "systemctl start " +
        TELEGRAM_SERVICE,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Failed to start Telegram bot.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "Telegram bot started.\n";


    return true;
}


// ============================================================
// STOP
// ============================================================

bool TelegramBot::stopService()
{
    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "systemctl stop " +
        TELEGRAM_SERVICE,
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
// RESTART
// ============================================================

bool TelegramBot::restartService()
{
    std::cout
        << "\nRestarting Telegram bot...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "systemctl restart " +
        TELEGRAM_SERVICE,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Failed to restart Telegram bot.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "Telegram bot restarted.\n";


    return true;
}


// ============================================================
// DISABLE
// ============================================================

bool TelegramBot::disableService()
{
    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        "systemctl disable " +
        TELEGRAM_SERVICE,
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
// SERVICE EXISTS
// ============================================================

bool TelegramBot::serviceExists()
{
    std::string output;

    int exitCode = -1;


    executeRemote(
        "test -f " +
        shellQuote(
            TELEGRAM_SERVICE_PATH
        ),
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


// ============================================================
// SERVICE ACTIVE
// ============================================================

bool TelegramBot::serviceIsActive()
{
    std::string output;

    int exitCode = -1;


    executeRemote(
        "systemctl is-active --quiet " +
        TELEGRAM_SERVICE,
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


// ============================================================
// RANDOM VERIFICATION CODE
// ============================================================

std::string TelegramBot::generateRandomCode()
{
    std::random_device rd;

    std::mt19937 generator(
        rd()
    );


    std::uniform_int_distribution<int>
        distribution(
            100000,
            999999
        );


    return std::to_string(
        distribution(generator)
    );
}


// ============================================================
// GENERATE VERIFICATION CODE
// ============================================================

bool TelegramBot::generateVerificationCode()
{
    if (!serviceExists())
    {
        std::cout
            << "\nTelegram bot is not installed.\n";

        return false;
    }


    std::string code =
        generateRandomCode();


    long long now =
        static_cast<long long>(
            std::time(nullptr)
            );


    long long expires =
        now + 300;


    std::ostringstream json;


    json
        << "{\n"
        << "    \"code\": \""
        << code
        << "\",\n"
        << "    \"created_at\": "
        << now
        << ",\n"
        << "    \"expires_at\": "
        << expires
        << "\n"
        << "}\n";


    std::string encoded =
        base64Encode(
            json.str()
        );


    std::string command =
        "echo " +
        shellQuote(encoded) +
        " | base64 -d > " +
        shellQuote(
            TELEGRAM_VERIFICATION
        ) +
        " && "
        "chmod 600 " +
        shellQuote(
            TELEGRAM_VERIFICATION
        ) +
        " && "
        "chown root:root " +
        shellQuote(
            TELEGRAM_VERIFICATION
        );


    std::string output;

    int exitCode = -1;


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create verification file.\n";

        return false;
    }


    std::cout
        << "\n";


    std::cout
        << "============================================\n";

    std::cout
        << "        TELEGRAM VERIFICATION\n";

    std::cout
        << "============================================\n\n";


    std::cout
        << "Verification code: "
        << code
        << "\n\n";


    std::cout
        << "Valid for: 5 minutes\n\n";


    std::cout
        << "Open your ServerGuard Telegram bot and send:\n\n";


    std::cout
        << "/start "
        << code
        << "\n\n";


    std::cout
        << "============================================\n";


    return true;
}


// ============================================================
// PUBLIC GENERATE CODE
// ============================================================

bool TelegramBot::generateCode()
{
    return generateVerificationCode();
}


// ============================================================
// REMOVE INSTALLATION
// ============================================================

bool TelegramBot::removeInstallation()
{
    std::cout
        << "\nRemoving Telegram bot...\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "systemctl stop " +
        TELEGRAM_SERVICE +
        " 2>/dev/null || true; "
        "systemctl disable " +
        TELEGRAM_SERVICE +
        " 2>/dev/null || true; "
        "rm -f " +
        shellQuote(
            TELEGRAM_SERVICE_PATH
        ) +
        "; "
        "systemctl daemon-reload; "
        "rm -rf " +
        shellQuote(
            TELEGRAM_DIR
        ) +
        "; "
        "rm -rf " +
        shellQuote(
            TELEGRAM_CODE_BACKUP
        );


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Failed to remove Telegram bot.\n";

        return false;
    }


    std::cout
        << "Telegram bot removed.\n";


    return true;
}


// ============================================================
// DOWNLOAD UPDATE FILE
// ============================================================
//
// Kept from the original implementation because other update
// operations use this helper.
//
// The main Telegram update now uses the full GitHub repository.
// ============================================================

bool TelegramBot::downloadUpdateFile(
    const std::string& url,
    const std::string& destination
)
{
    std::cout
        << "Downloading:\n"
        << url
        << "\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "curl -fL --silent --show-error "
        "--connect-timeout 15 "
        "--max-time 120 "
        "--retry 2 "
        "--retry-delay 2 "
        "-o " +
        shellQuote(destination) +
        " " +
        shellQuote(url);


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


        return false;
    }


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        "test -s " +
        shellQuote(destination),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Downloaded file is empty or missing.\n";

        return false;
    }


    std::cout
        << "Download successful.\n";


    return true;
}


// ============================================================
// CHECK PYTHON SYNTAX
// ============================================================

bool TelegramBot::checkPythonSyntax(
    const std::string& file
)
{
    std::cout
        << "Checking Python syntax:\n"
        << file
        << "\n";


    std::string output;

    int exitCode = -1;


    std::string python =
        TELEGRAM_VENV +
        "/bin/python";


    if (!executeRemote(
        shellQuote(python) +
        " -m py_compile " +
        shellQuote(file),
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Python syntax check FAILED.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "Python syntax is valid.\n";


    return true;
}


// ============================================================
// REQUIREMENTS EXISTS
// ============================================================

bool TelegramBot::requirementsExists()
{
    std::string output;

    int exitCode = -1;


    std::string requirements =
        TELEGRAM_DIR +
        "/requirements.txt";


    executeRemote(
        "test -s " +
        shellQuote(requirements),
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


// ============================================================
// UPDATE REQUIREMENTS
// ============================================================

bool TelegramBot::updateRequirements()
{
    std::cout
        << "\nUpdating Python libraries from requirements.txt...\n";


    std::string output;

    int exitCode = -1;


    std::string python =
        TELEGRAM_VENV +
        "/bin/python";


    std::string requirements =
        TELEGRAM_DIR +
        "/requirements.txt";


    std::string command =
        shellQuote(python) +
        " -m pip install --upgrade "
        "-r " +
        shellQuote(requirements);


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Failed to update Python libraries.\n";


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
        << "Python libraries updated.\n";


    return true;
}


// ============================================================
// UPDATE PYTHON LIBRARIES
// ============================================================

bool TelegramBot::updatePythonLibraries()
{
    std::cout
        << "\n============================================\n";

    std::cout
        << "          PYTHON LIBRARY UPDATE\n";

    std::cout
        << "============================================\n\n";


    // ========================================================
    // REQUIREMENTS.TXT
    // ========================================================

    if (requirementsExists())
    {
        std::cout
            << "requirements.txt found.\n";

        return updateRequirements();
    }


    // ========================================================
    // FALLBACK
    // ========================================================

    std::cout
        << "requirements.txt was not found.\n";

    std::cout
        << "Using aiogram update fallback.\n";


    std::string output;

    int exitCode = -1;


    std::string python =
        TELEGRAM_VENV +
        "/bin/python";


    std::string command =
        shellQuote(python) +
        " -m pip install --upgrade aiogram";


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Failed to update aiogram.\n";


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
        << "aiogram updated successfully.\n";


    return true;
}


// ============================================================
// BACKUP TELEGRAM CODE
// ============================================================
//
// Creates a backup of ALL BOT CODE.
//
// Preserved runtime data is intentionally excluded:
//   telegram.conf
//   verification.json
//   owner.json
//   queue/
//   venv/
// ============================================================

bool TelegramBot::backupTelegramCode()
{
    std::cout
        << "\nCreating complete Telegram bot backup...\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "rm -rf " +
        shellQuote(TELEGRAM_CODE_BACKUP) +
        " && "
        "mkdir -p " +
        shellQuote(TELEGRAM_CODE_BACKUP) +
        " && "
        "find " +
        shellQuote(TELEGRAM_DIR) +
        " -mindepth 1 -maxdepth 1 "
        "! -name telegram.conf "
        "! -name verification.json "
        "! -name owner.json "
        "! -name queue "
        "! -name venv "
        "! -name .repository_update "
        "-exec cp -a {} " +
        shellQuote(TELEGRAM_CODE_BACKUP) +
        "/ \\;";


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot create complete Telegram backup.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "Complete Telegram bot backup created:\n"
        << TELEGRAM_CODE_BACKUP
        << "\n";


    return true;
}


// ============================================================
// CLEAR TELEGRAM CODE
// ============================================================
//
// Deletes old bot code but preserves runtime data.
// ============================================================

bool TelegramBot::clearTelegramCode()
{
    std::cout
        << "\nRemoving old Telegram bot code...\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "find " +
        shellQuote(TELEGRAM_DIR) +
        " -mindepth 1 -maxdepth 1 "
        "! -name telegram.conf "
        "! -name verification.json "
        "! -name owner.json "
        "! -name queue "
        "! -name venv "
        "! -name .repository_update "
        "-exec rm -rf {} \\;";


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot remove old Telegram bot code.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    std::cout
        << "Old Telegram bot code removed.\n";


    return true;
}


// ============================================================
// RESTORE TELEGRAM CODE
// ============================================================

bool TelegramBot::restoreTelegramCode()
{
    std::cout
        << "\nRestoring previous Telegram bot version...\n";


    std::string output;

    int exitCode = -1;


    if (!clearTelegramCode())
    {
        std::cout
            << "Cannot clear failed Telegram version.\n";

        return false;
    }


    std::string command =
        "test -d " +
        shellQuote(TELEGRAM_CODE_BACKUP);


    if (!executeRemote(
        command,
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "Telegram backup does not exist.\n";

        return false;
    }


    command =
        "find " +
        shellQuote(TELEGRAM_CODE_BACKUP) +
        " -mindepth 1 -maxdepth 1 "
        "-exec cp -a {} " +
        shellQuote(TELEGRAM_DIR) +
        "/ \\;";


    if (!executeRemote(
        command,
        output,
        exitCode,
        true
    ))
    {
        std::cout
            << "Cannot restore Telegram bot backup.\n";


        if (!output.empty())
        {
            std::cout
                << output
                << "\n";
        }


        return false;
    }


    setRepositoryPermissions();


    std::cout
        << "Previous Telegram bot version restored.\n";


    return true;
}


// ============================================================
// UPDATE BOT
// ============================================================

bool TelegramBot::updateBot()
{
    std::cout
        << "\n";

    std::cout
        << "============================================\n";

    std::cout
        << "          SERVERGUARD TELEGRAM UPDATE\n";

    std::cout
        << "============================================\n\n";


    // ========================================================
    // ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        std::cout
            << "\nUpdate stopped.\n";

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
    // UNZIP
    // ========================================================

    if (!ensureUnzip())
    {
        return false;
    }


    // ========================================================
    // CHECK INSTALLATION
    // ========================================================

    if (!serviceExists())
    {
        std::cout
            << "\nTelegram bot is not installed.\n";

        std::cout
            << "Install the bot first.\n";

        return false;
    }


    if (!checkScript())
    {
        std::cout
            << "\nTelegram bot script does not exist.\n";

        return false;
    }


    // ========================================================
    // CHECK VENV
    // ========================================================

    std::string output;

    int exitCode = -1;


    std::string python =
        TELEGRAM_VENV +
        "/bin/python";


    if (!executeRemote(
        "test -x " +
        shellQuote(python),
        output,
        exitCode,
        false
    ))
    {
        std::cout
            << "\nTelegram virtual environment is missing.\n";

        std::cout
            << "Run Install / configure bot first.\n";

        return false;
    }


    // ========================================================
    // DIRECTORIES
    // ========================================================

    if (!createDirectories())
    {
        return false;
    }


    // ========================================================
    // CHECK CURRENT SERVICE
    // ========================================================

    bool wasActive =
        serviceIsActive();


    if (wasActive)
    {
        std::cout
            << "\nStopping Telegram bot before update...\n";


        if (!stopService())
        {
            std::cout
                << "Cannot stop Telegram bot.\n";

            return false;
        }
    }
    else
    {
        std::cout
            << "\nTelegram bot is currently inactive.\n";
    }


    // ========================================================
    // PREPARE TEMPORARY UPDATE
    // ========================================================

    executeRemote(
        "rm -rf " +
        shellQuote(TELEGRAM_UPDATE_DIR) +
        " " +
        shellQuote(TELEGRAM_UPDATE_ZIP),
        output,
        exitCode,
        true
    );


    // ========================================================
    // DOWNLOAD COMPLETE REPOSITORY
    // ========================================================

    if (!downloadRepositoryArchive(
        TELEGRAM_UPDATE_ZIP
    ))
    {
        std::cout
            << "\nNew Telegram repository could not be downloaded.\n";


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // EXTRACT COMPLETE REPOSITORY
    // ========================================================

    std::string repositoryRoot;


    if (!extractRepository(
        TELEGRAM_UPDATE_ZIP,
        TELEGRAM_UPDATE_DIR,
        repositoryRoot
    ))
    {
        std::cout
            << "\nNew Telegram repository could not be extracted.\n";


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // VALIDATE COMPLETE REPOSITORY
    // ========================================================

    if (!validateRepository(
        repositoryRoot
    ))
    {
        std::cout
            << "\nNew Telegram repository failed validation.\n";

        std::cout
            << "Existing bot was NOT replaced.\n";


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // BACKUP CURRENT BOT
    // ========================================================

    if (!backupTelegramCode())
    {
        std::cout
            << "\nBackup failed.\n";

        std::cout
            << "Existing bot was NOT replaced.\n";


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // REMOVE OLD CODE
    // ========================================================

    if (!clearTelegramCode())
    {
        std::cout
            << "\nCannot remove old Telegram bot code.\n";


        restoreTelegramCode();


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // INSTALL COMPLETE NEW REPOSITORY
    // ========================================================

    std::cout
        << "\nInstalling new Telegram repository...\n";


    if (!installRepositoryFiles(
        repositoryRoot
    ))
    {
        std::cout
            << "\nCannot install new Telegram repository.\n";


        restoreTelegramCode();


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // FINAL MAIN SCRIPT CHECK
    // ========================================================

    if (!checkScript())
    {
        std::cout
            << "\nNew repository does not contain telegram_bot.py.\n";

        std::cout
            << "Restoring previous version...\n";


        restoreTelegramCode();


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // UPDATE PYTHON LIBRARIES
    // ========================================================

    if (!updatePythonLibraries())
    {
        std::cout
            << "\nPython library update failed.\n";

        std::cout
            << "Restoring previous Telegram bot...\n";


        restoreTelegramCode();


        // Try to restore dependencies from previous
        // requirements.txt if it existed in the backup.

        std::string oldRequirements =
            TELEGRAM_CODE_BACKUP +
            "/requirements.txt";


        output.clear();

        exitCode = -1;


        if (executeRemote(
            "test -s " +
            shellQuote(oldRequirements),
            output,
            exitCode,
            false
        ))
        {
            std::cout
                << "Restoring previous Python requirements...\n";


            executeRemote(
                shellQuote(python) +
                " -m pip install --upgrade -r " +
                shellQuote(oldRequirements),
                output,
                exitCode,
                true
            );
        }


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // FINAL PYTHON SYNTAX CHECK
    // ========================================================

    std::cout
        << "\nPerforming final Python syntax check...\n";


    if (!checkPythonSyntax(
        TELEGRAM_SCRIPT
    ))
    {
        std::cout
            << "\nFinal syntax check failed.\n";

        std::cout
            << "Restoring previous Telegram bot...\n";


        restoreTelegramCode();


        // Restore old requirements if possible.

        std::string oldRequirements =
            TELEGRAM_CODE_BACKUP +
            "/requirements.txt";


        output.clear();

        exitCode = -1;


        if (executeRemote(
            "test -s " +
            shellQuote(oldRequirements),
            output,
            exitCode,
            false
        ))
        {
            executeRemote(
                shellQuote(python) +
                " -m pip install --upgrade -r " +
                shellQuote(oldRequirements),
                output,
                exitCode,
                true
            );
        }


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        if (wasActive)
        {
            startService();
        }


        return false;
    }


    // ========================================================
    // RELOAD SYSTEMD
    // ========================================================

    if (!reloadSystemd())
    {
        std::cout
            << "\nWarning: systemd reload failed.\n";
    }


    // ========================================================
    // START UPDATED BOT
    // ========================================================

    std::cout
        << "\nStarting updated Telegram bot...\n";


    if (!startService())
    {
        std::cout
            << "\nUpdated Telegram bot failed to start.\n";

        std::cout
            << "Restoring previous version...\n";


        restoreTelegramCode();


        // Restore old dependencies.

        std::string oldRequirements =
            TELEGRAM_CODE_BACKUP +
            "/requirements.txt";


        output.clear();

        exitCode = -1;


        if (executeRemote(
            "test -s " +
            shellQuote(oldRequirements),
            output,
            exitCode,
            false
        ))
        {
            executeRemote(
                shellQuote(python) +
                " -m pip install --upgrade -r " +
                shellQuote(oldRequirements),
                output,
                exitCode,
                true
            );
        }


        reloadSystemd();


        std::cout
            << "Starting previous version...\n";


        startService();


        std::this_thread::sleep_for(
            std::chrono::seconds(1)
        );


        if (serviceIsActive())
        {
            std::cout
                << "Previous Telegram bot version restored successfully.\n";
        }
        else
        {
            std::cout
                << "WARNING: Previous bot version was restored, "
                "but service is not active.\n";
        }


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        showUpdateLogs();

        return false;
    }


    // ========================================================
    // WAIT
    // ========================================================

    std::cout
        << "\nWaiting for Telegram bot...\n";


    std::this_thread::sleep_for(
        std::chrono::seconds(2)
    );


    // ========================================================
    // CHECK
    // ========================================================

    if (!serviceIsActive())
    {
        std::cout
            << "\nUpdated Telegram bot is not active.\n";

        std::cout
            << "Restoring previous version...\n";


        restoreTelegramCode();


        // Restore old Python requirements.

        std::string oldRequirements =
            TELEGRAM_CODE_BACKUP +
            "/requirements.txt";


        output.clear();

        exitCode = -1;


        if (executeRemote(
            "test -s " +
            shellQuote(oldRequirements),
            output,
            exitCode,
            false
        ))
        {
            executeRemote(
                shellQuote(python) +
                " -m pip install --upgrade -r " +
                shellQuote(oldRequirements),
                output,
                exitCode,
                true
            );
        }


        reloadSystemd();


        startService();


        std::this_thread::sleep_for(
            std::chrono::seconds(1)
        );


        if (serviceIsActive())
        {
            std::cout
                << "Previous Telegram bot version restored.\n";
        }
        else
        {
            std::cout
                << "WARNING: Telegram bot is still inactive.\n";
        }


        executeRemote(
            "rm -rf " +
            shellQuote(TELEGRAM_UPDATE_DIR) +
            " " +
            shellQuote(TELEGRAM_UPDATE_ZIP),
            output,
            exitCode,
            true
        );


        showUpdateLogs();

        return false;
    }


    // ========================================================
    // CLEAN TEMPORARY FILES
    // ========================================================

    executeRemote(
        "rm -rf " +
        shellQuote(TELEGRAM_UPDATE_DIR) +
        " " +
        shellQuote(TELEGRAM_UPDATE_ZIP),
        output,
        exitCode,
        true
    );


    // ========================================================
    // SUCCESS
    // ========================================================

    std::cout
        << "\n";

    std::cout
        << "============================================\n";

    std::cout
        << "       TELEGRAM BOT UPDATED SUCCESSFULLY\n";

    std::cout
        << "============================================\n\n";


    std::cout
        << "Repository: Lukas6623/ServerGuardTelegram\n";

    std::cout
        << "Repository files: UPDATED\n";

    std::cout
        << "Python libraries: UPDATED\n";

    std::cout
        << "Configuration: PRESERVED\n";

    std::cout
        << "Verification data: PRESERVED\n";

    std::cout
        << "Owner data: PRESERVED\n";

    std::cout
        << "Queue: PRESERVED\n";

    std::cout
        << "Virtual environment: PRESERVED\n";

    std::cout
        << "Service: ACTIVE\n";


    std::cout
        << "\nBackup:\n"
        << TELEGRAM_CODE_BACKUP
        << "\n";


    return true;
}


// ============================================================
// SHOW UPDATE LOGS
// ============================================================

void TelegramBot::showUpdateLogs()
{
    std::cout
        << "\n";

    std::cout
        << "============================================\n";

    std::cout
        << "        TELEGRAM SERVICE LOGS\n";

    std::cout
        << "============================================\n\n";


    std::string logs;

    int exitCode = -1;


    executeRemote(
        "journalctl -u " +
        TELEGRAM_SERVICE +
        " -n 50 --no-pager",
        logs,
        exitCode,
        false
    );


    if (!logs.empty())
    {
        std::cout
            << logs;
    }


    std::cout
        << "\n";
}


// ============================================================
// INSTALL / CONFIGURE
// ============================================================

bool TelegramBot::install()
{
    std::cout
        << "\n";


    std::cout
        << "============================================\n";

    std::cout
        << "      INSTALL / CONFIGURE TELEGRAM\n";

    std::cout
        << "============================================\n\n";


    // ========================================================
    // ROOT / SUDO
    // ========================================================

    if (!checkRootOrSudo())
    {
        std::cout
            << "\nInstallation stopped.\n";

        return false;
    }


    // ========================================================
    // REQUIRED COMMANDS
    // ========================================================

    std::cout
        << "Checking required commands...\n";


    if (!commandExists("systemctl"))
    {
        std::cout
            << "systemctl is not available.\n";

        return false;
    }


    if (!commandExists("base64"))
    {
        std::cout
            << "base64 is not available.\n";

        return false;
    }


    if (!commandExists("curl"))
    {
        std::cout
            << "curl is not available.\n";

        std::cout
            << "It will be installed with Python dependencies.\n";
    }


    if (!commandExists("unzip"))
    {
        std::cout
            << "unzip is not available.\n";

        std::cout
            << "It will be installed with Python dependencies.\n";
    }


    // ========================================================
    // DIRECTORIES
    // ========================================================

    if (!createDirectories())
    {
        return false;
    }


    // ========================================================
    // PYTHON / VENV / AIOGRAM
    // ========================================================

    if (!installPythonDependencies())
    {
        return false;
    }


    // ========================================================
    // COMPLETE TELEGRAM REPOSITORY
    // ========================================================

    if (!downloadBot())
    {
        return false;
    }


    // ========================================================
    // PYTHON LIBRARIES FROM REPOSITORY
    // ========================================================

    if (!updatePythonLibraries())
    {
        std::cout
            << "\nFailed to install Python libraries required "
            "by Telegram repository.\n";

        return false;
    }


    // ========================================================
    // FINAL SCRIPT CHECK
    // ========================================================

    if (!checkScript())
    {
        std::cout
            << "\nTelegram bot script was not found.\n";

        return false;
    }


    if (!checkPythonSyntax(
        TELEGRAM_SCRIPT
    ))
    {
        std::cout
            << "\nTelegram bot Python syntax is invalid.\n";

        return false;
    }


    // ========================================================
    // CONFIG
    // ========================================================

    if (!createConfig())
    {
        return false;
    }


    // ========================================================
    // SERVICE
    // ========================================================

    if (!serviceExists())
    {
        if (!createSystemdService())
        {
            return false;
        }
    }
    else
    {
        std::cout
            << "\nTelegram systemd service already exists.\n";
    }


    // ========================================================
    // RELOAD
    // ========================================================

    if (!reloadSystemd())
    {
        return false;
    }


    // ========================================================
    // ENABLE
    // ========================================================

    if (!enableService())
    {
        return false;
    }


    // ========================================================
    // START
    // ========================================================

    if (!startService())
    {
        return false;
    }


    // ========================================================
    // WAIT
    // ========================================================

    std::cout
        << "\nWaiting for Telegram bot...\n";


    std::this_thread::sleep_for(
        std::chrono::seconds(2)
    );


    // ========================================================
    // CHECK
    // ========================================================

    std::cout
        << "\nChecking Telegram bot service...\n";


    if (serviceIsActive())
    {
        std::cout
            << "\n";


        std::cout
            << "============================================\n";

        std::cout
            << "       TELEGRAM BOT ENABLED\n";

        std::cout
            << "============================================\n\n";


        std::cout
            << "Repository: Lukas6623/ServerGuardTelegram\n";


        std::cout
            << "Service: "
            << TELEGRAM_SERVICE
            << "\n";


        std::cout
            << "Status: ACTIVE\n";


        std::cout
            << "Startup: ENABLED\n";


        std::cout
            << "Bot: RUNNING\n";


        std::cout
            << "Python: VIRTUAL ENVIRONMENT\n";


        if (requirementsExists())
        {
            std::cout
                << "Requirements: INSTALLED\n";
        }
        else
        {
            std::cout
                << "Requirements: NOT PRESENT\n";
        }


        std::cout
            << "aiogram: INSTALLED\n";


        return true;
    }


    // ========================================================
    // FAILED
    // ========================================================

    std::cout
        << "\nTelegram bot failed to start.\n";


    std::cout
        << "\nLast service logs:\n";


    std::cout
        << "--------------------------------------------\n";


    std::string logs;

    int logExitCode = -1;


    executeRemote(
        "journalctl -u " +
        TELEGRAM_SERVICE +
        " -n 50 --no-pager",
        logs,
        logExitCode,
        false
    );


    if (!logs.empty())
    {
        std::cout
            << logs;
    }


    std::cout
        << "--------------------------------------------\n";


    return false;
}


// ============================================================
// STATUS
// ============================================================

bool TelegramBot::isActive()
{
    return serviceIsActive();
}


// ============================================================
// MENU
// ============================================================

void TelegramBot::menu()
{
    while (true)
    {
        std::cout
            << "\n";


        std::cout
            << "============================================\n";


        std::cout
            << "             TELEGRAM BOT\n";


        std::cout
            << "============================================\n\n";


        bool active =
            serviceIsActive();


        std::cout
            << "Telegram bot: "
            <<
            (
                active
                ? "ACTIVE"
                : "INACTIVE"
                )
            << "\n\n";


        // ====================================================
        // MENU
        // ====================================================

        std::cout
            << "1. Install / configure bot\n";

        std::cout
            << "2. Generate verification code\n";

        std::cout
            << "3. Start bot\n";

        std::cout
            << "4. Stop bot\n";

        std::cout
            << "5. Restart bot\n";

        std::cout
            << "6. Disable automatic startup\n";

        std::cout
            << "7. Update bot\n";

        std::cout
            << "8. Check status\n";

        std::cout
            << "9. Show logs\n";

        std::cout
            << "10. Remove bot\n";

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
        // INSTALL / CONFIGURE
        // ====================================================

        if (choice == "1")
        {
            install();

            continue;
        }


        // ====================================================
        // VERIFICATION
        // ====================================================

        if (choice == "2")
        {
            generateCode();

            continue;
        }


        // ====================================================
        // START
        // ====================================================

        if (choice == "3")
        {
            if (!serviceExists())
            {
                std::cout
                    << "\nTelegram bot is not installed.\n";

                continue;
            }


            if (startService())
            {
                std::this_thread::sleep_for(
                    std::chrono::seconds(1)
                );


                if (serviceIsActive())
                {
                    std::cout
                        << "Telegram bot is ACTIVE.\n";
                }
                else
                {
                    std::cout
                        << "Telegram bot failed to start.\n";
                }
            }


            continue;
        }


        // ====================================================
        // STOP
        // ====================================================

        if (choice == "4")
        {
            if (!serviceExists())
            {
                std::cout
                    << "\nTelegram bot is not installed.\n";

                continue;
            }


            if (stopService())
            {
                std::cout
                    << "Telegram bot stopped.\n";
            }


            continue;
        }


        // ====================================================
        // RESTART
        // ====================================================

        if (choice == "5")
        {
            if (!serviceExists())
            {
                std::cout
                    << "\nTelegram bot is not installed.\n";

                continue;
            }


            restartService();


            std::this_thread::sleep_for(
                std::chrono::seconds(1)
            );


            if (serviceIsActive())
            {
                std::cout
                    << "Telegram bot is ACTIVE.\n";
            }


            continue;
        }


        // ====================================================
        // DISABLE
        // ====================================================

        if (choice == "6")
        {
            if (!serviceExists())
            {
                std::cout
                    << "\nTelegram bot is not installed.\n";

                continue;
            }


            if (disableService())
            {
                std::cout
                    << "Automatic startup disabled.\n";
            }


            continue;
        }


        // ====================================================
        // UPDATE
        // ====================================================

        if (choice == "7")
        {
            updateBot();

            continue;
        }


        // ====================================================
        // STATUS
        // ====================================================

        if (choice == "8")
        {
            if (!serviceExists())
            {
                std::cout
                    << "\nTelegram bot is not installed.\n";

                continue;
            }


            std::string output;

            int exitCode = -1;


            executeRemote(
                "systemctl status " +
                TELEGRAM_SERVICE +
                " --no-pager",
                output,
                exitCode,
                false
            );


            std::cout
                << "\n";


            if (!output.empty())
            {
                std::cout
                    << output;
            }


            continue;
        }


        // ====================================================
        // LOGS
        // ====================================================

        if (choice == "9")
        {
            if (!serviceExists())
            {
                std::cout
                    << "\nTelegram bot is not installed.\n";

                continue;
            }


            std::string output;

            int exitCode = -1;


            executeRemote(
                "journalctl -u " +
                TELEGRAM_SERVICE +
                " -n 50 --no-pager",
                output,
                exitCode,
                false
            );


            std::cout
                << "\n";


            std::cout
                << "============================================\n";


            std::cout
                << "             TELEGRAM LOGS\n";


            std::cout
                << "============================================\n\n";


            if (!output.empty())
            {
                std::cout
                    << output;
            }


            std::cout
                << "\n";


            continue;
        }


        // ====================================================
        // REMOVE
        // ====================================================

        if (choice == "10")
        {
            if (!serviceExists())
            {
                std::cout
                    << "\nTelegram bot is not installed.\n";

                continue;
            }


            std::cout
                << "\nWARNING: This will remove the Telegram bot.\n";


            std::cout
                << "Continue? (yes/no): ";


            std::string confirmation;


            std::getline(
                std::cin >> std::ws,
                confirmation
            );


            if (
                confirmation == "yes"
                )
            {
                removeInstallation();
            }
            else
            {
                std::cout
                    << "Cancelled.\n";
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