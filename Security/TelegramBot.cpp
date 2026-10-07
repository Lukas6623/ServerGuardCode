// ============================================================
// TelegramBot.cpp — ЯДРО класса.
//
// Здесь находится всё, что НЕ относится к отдельным операциям
// установки/обновления/удаления/старта/стопа/рестарта/
// автозапуска/генерации кода (они вынесены в свои папки —
// см. карту в TelegramBot.h). А именно:
//
//   - конструктор
//   - выполнение команд по SSH (executeRemote), sudo-аутентификация
//   - проверка root/sudo, наличия команд
//   - установка python3/venv/pip/aiogram
//   - скачивание, распаковка, валидация и установка
//     GitHub-репозитория бота
//   - конфиг бота (BOT_TOKEN), systemd unit-файл, reload systemd
//   - startService() — общий хелпер запуска (используется
//     install/update/restart/меню)
//   - проверки serviceExists/serviceIsActive/checkScript
//   - бэкап/очистка/восстановление кода бота
//   - обновление python-библиотек
//   - консольное меню (menu)
//   - web-статус и web-логи (webStatus, webLogs, webStart)
// ============================================================

#include "TelegramBot.h"
#include "TelegramBotInternal.h"

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>


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
        output = "SSH session is invalid.";

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
        libssh2_channel_open_session(session);

    if (!channel)
    {
        output = "Cannot open SSH channel.";

        return false;
    }


    libssh2_channel_handle_extended_data2(
        channel,
        LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
    );


    // ========================================================
    // EXECUTE
    // ========================================================

    if (libssh2_channel_exec(channel, finalCommand.c_str()) != 0)
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
        int rc = static_cast<int>(
            libssh2_channel_read(channel, buffer, sizeof(buffer) - 1)
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


    exitCode = libssh2_channel_get_exit_status(channel);


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
        std::cout << "Sudo password is empty.\n";

        return false;
    }

    std::cout << "Authenticating sudo...\n";


    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(session);

    if (!channel)
    {
        std::cout << "Cannot open sudo channel.\n";

        return false;
    }


    libssh2_channel_request_pty(channel, "xterm");

    libssh2_channel_handle_extended_data2(
        channel,
        LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
    );


    const char* command = "sudo -S -p '' -v";


    if (libssh2_channel_exec(channel, command) != 0)
    {
        libssh2_channel_free(channel);

        return false;
    }


    std::string password = sudoPassword + "\n";

    size_t totalWritten = 0;


    while (totalWritten < password.size())
    {
        int written = static_cast<int>(
            libssh2_channel_write(
                channel,
                password.c_str() + totalWritten,
                password.size() - totalWritten
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

        totalWritten += static_cast<size_t>(written);
    }


    libssh2_channel_send_eof(channel);


    char buffer[4096];

    std::string output;


    while (true)
    {
        int rc = static_cast<int>(
            libssh2_channel_read(channel, buffer, sizeof(buffer) - 1)
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


    int exitCode = libssh2_channel_get_exit_status(channel);


    libssh2_channel_free(channel);


    if (exitCode == 0)
    {
        sudoAuthenticated = true;

        std::cout << "Sudo authentication successful.\n";

        return true;
    }


    sudoAuthenticated = false;

    std::cout << "Sudo authentication failed.\n";


    if (!output.empty())
    {
        std::cout << output << "\n";
    }


    return false;
}


// ============================================================
// COMMAND EXISTS
// ============================================================

bool TelegramBot::commandExists(const std::string& command)
{
    std::string output;

    int exitCode = -1;


    std::string remoteCommand =
        "command -v " + shellQuote(command) + " >/dev/null 2>&1";


    executeRemote(remoteCommand, output, exitCode, false);


    return exitCode == 0;
}


// ============================================================
// ROOT / SUDO
// ============================================================

bool TelegramBot::checkRootOrSudo()
{
    std::string output;

    int exitCode = -1;


    if (!executeRemote("id -u", output, exitCode, false))
    {
        std::cout << "Cannot determine remote user.\n";

        return false;
    }


    std::stringstream stream(output);

    int uid = -1;

    stream >> uid;


    if (uid == 0)
    {
        sudoRequired = false;

        sudoAuthenticated = true;

        std::cout << "Remote user is root.\n";

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


// ============================================================
// CREATE DIRECTORIES
// ============================================================

bool TelegramBot::createDirectories()
{
    std::cout << "Creating Telegram directories...\n";


    std::string output;

    int exitCode = -1;


    std::string command =
        "mkdir -p " +
        shellQuote(TELEGRAM_DIR) +
        " " +
        shellQuote(TELEGRAM_QUEUE);


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create Telegram directories.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    std::cout << "Telegram directories created.\n";


    return true;
}


// ============================================================
// INSTALL PYTHON DEPENDENCIES
// ============================================================

bool TelegramBot::installPythonDependencies()
{
    std::cout << "\nChecking Python environment...\n";


    // ========================================================
    // PYTHON3
    // ========================================================

    if (!commandExists("python3"))
    {
        std::cout << "Python3 not found.\n";

        std::cout << "Installing Python3...\n";


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
            std::cout << "Failed to install Python3.\n";

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
        std::cout << "apt-get not found.\n";

        return false;
    }


    // ========================================================
    // VENV / PIP / CURL / UNZIP
    // ========================================================

    std::cout << "Checking Python packages...\n";


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
        std::cout << "Failed to install Python requirements.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }


    // ========================================================
    // CREATE VENV ONLY IF MISSING
    // ========================================================

    std::cout << "Checking Telegram virtual environment...\n";


    std::string venvPython = TELEGRAM_VENV + "/bin/python";


    bool venvExists = executeRemote(
        "test -x " + shellQuote(venvPython),
        output,
        exitCode,
        false
    );


    if (!venvExists)
    {
        std::cout << "Virtual environment not found.\n";

        std::cout << "Creating virtual environment...\n";


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
            std::cout << "Failed to create virtual environment.\n";

            if (!output.empty())
                std::cout << output << "\n";

            return false;
        }


        std::cout << "Virtual environment created.\n";
    }
    else
    {
        std::cout << "Virtual environment already exists.\n";
    }


    // ========================================================
    // CHECK PYTHON
    // ========================================================

    output.clear();

    exitCode = -1;


    if (!executeRemote(
        shellQuote(venvPython) + " --version",
        output,
        exitCode,
        true
    ))
    {
        std::cout << "Virtual environment Python is not working.\n";

        return false;
    }


    if (!output.empty())
    {
        std::cout << output;
    }


    // ========================================================
    // CHECK AIOGRAM
    // ========================================================

    std::cout << "Checking aiogram...\n";


    output.clear();

    exitCode = -1;


    bool aiogramInstalled = executeRemote(
        shellQuote(venvPython) + " -c \"import aiogram\"",
        output,
        exitCode,
        false
    );


    if (!aiogramInstalled)
    {
        std::cout << "aiogram is not installed.\n";

        std::cout << "Installing aiogram...\n";


        output.clear();

        exitCode = -1;


        if (!executeRemote(
            shellQuote(venvPython) + " -m pip install aiogram",
            output,
            exitCode,
            true
        ))
        {
            std::cout << "Failed to install aiogram.\n";

            if (!output.empty())
                std::cout << output << "\n";

            return false;
        }


        std::cout << "aiogram installed.\n";
    }
    else
    {
        std::cout << "aiogram is already installed.\n";
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
        "test -f " + shellQuote(TELEGRAM_SCRIPT),
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


    std::cout << "unzip is not installed.\n";

    std::cout << "Installing unzip...\n";


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
        std::cout << "Cannot install unzip.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    return commandExists("unzip");
}


// ============================================================
// DOWNLOAD REPOSITORY ARCHIVE
// ============================================================

bool TelegramBot::downloadRepositoryArchive(const std::string& archivePath)
{
    std::cout << "\nDownloading Telegram bot repository...\n";

    std::cout << "Repository:\n" << GITHUB_TELEGRAM_REPOSITORY_ZIP << "\n\n";


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
        shellQuote(GITHUB_TELEGRAM_REPOSITORY_ZIP);


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Repository download failed.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        "test -s " + shellQuote(archivePath),
        output,
        exitCode,
        false
    ))
    {
        std::cout << "Downloaded repository archive is empty.\n";

        return false;
    }


    std::cout << "Repository archive downloaded successfully.\n";


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

    std::cout << "\nExtracting Telegram bot repository...\n";

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

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot extract Telegram repository.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    // ========================================================
    // FIND telegram_bot.py ANYWHERE IN EXTRACTED REPOSITORY
    //
    // The GitHub repository sometimes ships the bot code
    // packed inside a NESTED .zip file instead of raw files.
    // If telegram_bot.py is not found directly, look for any
    // .zip files inside the extracted tree and unpack them in
    // place, then search again. Repeat until the script is
    // found or there is nothing left to unpack.
    // ========================================================

    std::cout << "Searching extracted repository for telegram_bot.py...\n";

    std::string mainScript;

    const int MAX_NESTED_UNZIP_ITERATIONS = 5;

    for (int iteration = 0; iteration < MAX_NESTED_UNZIP_ITERATIONS; ++iteration)
    {
        output.clear();
        exitCode = -1;

        command =
            "find " +
            shellQuote(extractDirectory) +
            " -type f -name 'telegram_bot.py' "
            "-print -quit";

        if (!executeRemote(command, output, exitCode, false))
        {
            std::cout << "Cannot search extracted Telegram repository.\n";

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

        executeRemote(command, output, exitCode, false);

        std::string nestedZips = trim(output);

        if (nestedZips.empty())
        {
            // Nothing left to unpack.
            break;
        }

        std::cout << "Nested archive(s) found inside repository, extracting...\n";

        std::istringstream zipStream(nestedZips);
        std::string zipPath;

        while (std::getline(zipStream, zipPath))
        {
            zipPath = trim(zipPath);

            if (zipPath.empty())
            {
                continue;
            }

            std::cout << "Extracting nested archive:\n" << zipPath << "\n";

            std::string nestedExtractDir = zipPath + ".__extracted";

            std::string extractCommand =
                "unzip -q -o " +
                shellQuote(zipPath) +
                " -d " +
                shellQuote(nestedExtractDir) +
                " && rm -f " +
                shellQuote(zipPath);

            std::string extractOutput;
            int extractExitCode = -1;

            if (!executeRemote(extractCommand, extractOutput, extractExitCode, true))
            {
                std::cout << "Cannot extract nested archive:\n" << zipPath << "\n";

                if (!extractOutput.empty())
                {
                    std::cout << extractOutput << "\n";
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

        std::cout << "Extracted directory:\n" << extractDirectory << "\n";

        // Show extracted files to make debugging easier.

        output.clear();
        exitCode = -1;

        executeRemote(
            "find " + shellQuote(extractDirectory) + " -maxdepth 6 -print",
            output,
            exitCode,
            false
        );

        if (!output.empty())
        {
            std::cout << "\nExtracted repository contents:\n" << output << "\n";
        }

        return false;
    }

    // ========================================================
    // DETERMINE DIRECTORY CONTAINING telegram_bot.py
    // ========================================================

    output.clear();
    exitCode = -1;

    command = "dirname " + shellQuote(mainScript);

    if (!executeRemote(command, output, exitCode, false))
    {
        std::cout << "Cannot determine Telegram repository root.\n";

        return false;
    }

    repositoryRoot = trim(output);

    if (repositoryRoot.empty())
    {
        std::cout << "Repository root is empty.\n";

        return false;
    }

    // ========================================================
    // SHOW RESULT
    // ========================================================

    std::cout << "Telegram bot entry point found:\n" << mainScript << "\n";

    std::cout << "Repository root:\n" << repositoryRoot << "\n";

    return true;
}

// ============================================================
// VALIDATE REPOSITORY
// ============================================================

bool TelegramBot::validateRepository(const std::string& repositoryRoot)
{
    std::cout << "\nValidating Telegram repository...\n";

    // ========================================================
    // MAIN SCRIPT
    // ========================================================

    std::string mainScript = repositoryRoot + "/telegram_bot.py";

    std::string output;
    int exitCode = -1;

    if (!executeRemote("test -f " + shellQuote(mainScript), output, exitCode, false))
    {
        std::cout << "ERROR: telegram_bot.py was not found.\n";

        std::cout << "Expected:\n" << mainScript << "\n";

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
            std::cout << "\nFound telegram_bot.py files:\n" << output << "\n";
        }

        return false;
    }

    std::cout << "Main Telegram bot file found:\n" << mainScript << "\n";

    // ========================================================
    // CHECK REPOSITORY CONTENT
    // ========================================================

    std::cout << "\nChecking repository contents...\n";

    output.clear();
    exitCode = -1;

    executeRemote(
        "find " + shellQuote(repositoryRoot) + " -maxdepth 2 -print",
        output,
        exitCode,
        false
    );

    if (!output.empty())
    {
        std::cout << output << "\n";
    }

    // ========================================================
    // PYTHON SYNTAX
    // ========================================================

    std::cout << "Checking Python syntax for repository...\n";

    std::string python = TELEGRAM_VENV + "/bin/python";

    output.clear();
    exitCode = -1;

    std::string command =
        shellQuote(python) +
        " -m compileall -q " +
        shellQuote(repositoryRoot);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Repository Python syntax validation FAILED.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }

    std::cout << "All Python files passed syntax validation.\n";

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

    std::cout << "Repository validation successful.\n";

    return true;
}

// ============================================================
// SET REPOSITORY PERMISSIONS
// ============================================================

bool TelegramBot::setRepositoryPermissions()
{
    std::cout << "\nConfiguring Telegram repository permissions...\n";


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


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot configure repository permissions.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
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


    executeRemote(command, output, exitCode, true);


    std::cout << "Repository permissions configured.\n";


    return true;
}


// ============================================================
// INSTALL REPOSITORY FILES
// ============================================================

bool TelegramBot::installRepositoryFiles(const std::string& repositoryRoot)
{
    std::cout << "\nInstalling Telegram repository files...\n";


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


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot install repository files.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    if (!setRepositoryPermissions())
    {
        return false;
    }


    std::cout << "Telegram repository installed successfully.\n";


    return true;
}


// ============================================================
// DOWNLOAD BOT (repository download + extract + validate + install)
//
// Общий хелпер, используется как install(), так и updateBot().
// ============================================================

bool TelegramBot::downloadBot()
{
    std::cout << "\nDownloading Telegram bot repository...\n";


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

    if (!downloadRepositoryArchive(TELEGRAM_UPDATE_ZIP))
    {
        return false;
    }


    // ========================================================
    // EXTRACT
    // ========================================================

    std::string repositoryRoot;


    if (!extractRepository(TELEGRAM_UPDATE_ZIP, TELEGRAM_UPDATE_DIR, repositoryRoot))
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

    if (!validateRepository(repositoryRoot))
    {
        std::cout << "\nTelegram repository validation failed.\n";

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

    if (!installRepositoryFiles(repositoryRoot))
    {
        std::cout << "\nFailed to install Telegram repository.\n";

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
        std::cout << "Telegram bot script is missing after installation.\n";

        return false;
    }


    if (!checkPythonSyntax(TELEGRAM_SCRIPT))
    {
        std::cout << "Telegram bot Python syntax check failed.\n";

        return false;
    }


    std::cout << "\nTelegram bot repository installed successfully.\n";


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
        "test -s " + shellQuote(TELEGRAM_CONFIG),
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


    std::cout << "\n";

    std::cout << "Telegram Bot Token\n";

    std::cout << "------------------\n";

    std::cout << "Enter token: ";


    std::getline(std::cin >> std::ws, token);


    return token;
}


// ============================================================
// CREATE CONFIG
// ============================================================

bool TelegramBot::createConfig()
{
    if (configExists())
    {
        std::cout << "\nTelegram configuration already exists.\n";

        std::cout << "Existing bot token will be preserved.\n";

        return true;
    }


    std::cout << "\nConfiguring Telegram bot...\n";


    std::string token = readBotToken();


    if (token.empty())
    {
        std::cout << "Bot token cannot be empty.\n";

        return false;
    }


    // ========================================================
    // BASIC TOKEN VALIDATION
    // ========================================================

    std::size_t colon = token.find(':');


    if (colon == std::string::npos || colon == 0 || colon == token.size() - 1)
    {
        std::cout << "Telegram token format looks invalid.\n";

        std::cout << "Expected format:\n";

        std::cout << "123456789:AAxxxxxxxx...\n";

        return false;
    }


    std::string config = "BOT_TOKEN=" + token + "\n";


    std::string encoded = base64Encode(config);


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


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create Telegram configuration.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    std::cout << "Telegram configuration created.\n";


    return true;
}

bool TelegramBot::createConfig(
    const std::string& token
)
{
    // ========================================================
    // EXISTING CONFIG
    // ========================================================

    if (configExists())
    {
        std::cout
            << "\nTelegram configuration already exists.\n";

        std::cout
            << "Existing bot token will be preserved.\n";

        return true;
    }


    // ========================================================
    // VALIDATE TOKEN
    // ========================================================

    if (token.empty())
    {
        std::cout
            << "Telegram bot token cannot be empty.\n";

        return false;
    }


    // ========================================================
    // BASIC TELEGRAM TOKEN FORMAT CHECK
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


    // ========================================================
    // CREATE CONFIG
    // ========================================================

    std::string config =
        "BOT_TOKEN=" + token + "\n";


    std::string encoded =
        base64Encode(config);


    std::string command =
        "echo "
        + shellQuote(encoded)
        + " | base64 -d > "
        + shellQuote(TELEGRAM_CONFIG)
        + " && chmod 600 "
        + shellQuote(TELEGRAM_CONFIG)
        + " && chown root:root "
        + shellQuote(TELEGRAM_CONFIG);


    std::string output;

    int exitCode = -1;


    if (
        !executeRemote(
            command,
            output,
            exitCode,
            true
        )
        ||
        exitCode != 0
        )
    {
        std::cout
            << "Failed to create Telegram configuration.\n";

        return false;
    }


    // ========================================================
    // VERIFY CONFIG
    // ========================================================

    if (!configExists())
    {
        std::cout
            << "Telegram configuration was not created.\n";

        return false;
    }


    std::cout
        << "Telegram configuration created successfully.\n";


    return true;
}
// ============================================================
// CREATE SYSTEMD SERVICE
// ============================================================

bool TelegramBot::createSystemdService()
{
    std::cout << "\nCreating Telegram systemd service...\n";


    std::string service;


    service += "[Unit]\n";

    service += "Description=ServerGuard Telegram Security Bot\n";

    service += "After=network-online.target\n";

    service += "Wants=network-online.target\n\n";


    service += "[Service]\n";

    service += "Type=simple\n";

    service += "ExecStart=" + TELEGRAM_VENV + "/bin/python " + TELEGRAM_SCRIPT + "\n";

    service += "WorkingDirectory=" + TELEGRAM_DIR + "\n";

    service += "User=root\n";

    service += "Group=root\n";

    service += "Restart=always\n";

    service += "RestartSec=5\n";

    service += "Environment=PYTHONUNBUFFERED=1\n";

    service += "NoNewPrivileges=false\n\n";


    service += "[Install]\n";

    service += "WantedBy=multi-user.target\n";


    // ========================================================
    // BASE64
    // ========================================================

    std::string encoded = base64Encode(service);


    std::string command =
        "echo " +
        shellQuote(encoded) +
        " | base64 -d > " +
        shellQuote(TELEGRAM_SERVICE_PATH);


    std::string output;

    int exitCode = -1;


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create Telegram systemd service.\n";

        return false;
    }


    // ========================================================
    // PERMISSIONS
    // ========================================================

    command =
        "chmod 644 " +
        shellQuote(TELEGRAM_SERVICE_PATH) +
        " && "
        "chown root:root " +
        shellQuote(TELEGRAM_SERVICE_PATH);


    output.clear();

    exitCode = -1;


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot configure service permissions.\n";

        return false;
    }


    std::cout << "Telegram systemd service created.\n";


    return true;
}


// ============================================================
// RELOAD SYSTEMD
// ============================================================

bool TelegramBot::reloadSystemd()
{
    std::cout << "\nReloading systemd...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote("systemctl daemon-reload", output, exitCode, true))
    {
        std::cout << "systemd reload failed.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    std::cout << "systemd reloaded.\n";


    return true;
}


// ============================================================
// START  (общий хелпер запуска — используется install/update/restart/меню)
// ============================================================

bool TelegramBot::startService()
{
    std::cout << "\nStarting Telegram bot...\n";


    std::string output;

    int exitCode = -1;


    if (!executeRemote("systemctl start " + TELEGRAM_SERVICE, output, exitCode, true))
    {
        std::cout << "Failed to start Telegram bot.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    std::cout << "Telegram bot started.\n";


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
        "test -f " + shellQuote(TELEGRAM_SERVICE_PATH),
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
        "systemctl is-active --quiet " + TELEGRAM_SERVICE,
        output,
        exitCode,
        false
    );


    return exitCode == 0;
}


// ============================================================
// DOWNLOAD UPDATE FILE
//
// Универсальный хелпер скачивания одного файла. Используется
// другими операциями обновления.
// ============================================================

bool TelegramBot::downloadUpdateFile(
    const std::string& url,
    const std::string& destination
)
{
    std::cout << "Downloading:\n" << url << "\n";


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


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Download failed.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    output.clear();

    exitCode = -1;


    if (!executeRemote(
        "test -s " + shellQuote(destination),
        output,
        exitCode,
        false
    ))
    {
        std::cout << "Downloaded file is empty or missing.\n";

        return false;
    }


    std::cout << "Download successful.\n";


    return true;
}


// ============================================================
// CHECK PYTHON SYNTAX
// ============================================================

bool TelegramBot::checkPythonSyntax(const std::string& file)
{
    std::cout << "Checking Python syntax:\n" << file << "\n";


    std::string output;

    int exitCode = -1;


    std::string python = TELEGRAM_VENV + "/bin/python";


    if (!executeRemote(
        shellQuote(python) + " -m py_compile " + shellQuote(file),
        output,
        exitCode,
        true
    ))
    {
        std::cout << "Python syntax check FAILED.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    std::cout << "Python syntax is valid.\n";


    return true;
}


// ============================================================
// REQUIREMENTS EXISTS
// ============================================================

bool TelegramBot::requirementsExists()
{
    std::string output;

    int exitCode = -1;


    std::string requirements = TELEGRAM_DIR + "/requirements.txt";


    executeRemote(
        "test -s " + shellQuote(requirements),
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
    std::cout << "\nUpdating Python libraries from requirements.txt...\n";


    std::string output;

    int exitCode = -1;


    std::string python = TELEGRAM_VENV + "/bin/python";


    std::string requirements = TELEGRAM_DIR + "/requirements.txt";


    std::string command =
        shellQuote(python) +
        " -m pip install --upgrade "
        "-r " +
        shellQuote(requirements);


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Failed to update Python libraries.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    if (!output.empty())
    {
        std::cout << output;
    }


    std::cout << "Python libraries updated.\n";


    return true;
}


// ============================================================
// UPDATE PYTHON LIBRARIES
// ============================================================

bool TelegramBot::updatePythonLibraries()
{
    std::cout << "\n============================================\n";

    std::cout << "          PYTHON LIBRARY UPDATE\n";

    std::cout << "============================================\n\n";


    // ========================================================
    // REQUIREMENTS.TXT
    // ========================================================

    if (requirementsExists())
    {
        std::cout << "requirements.txt found.\n";

        return updateRequirements();
    }


    // ========================================================
    // FALLBACK
    // ========================================================

    std::cout << "requirements.txt was not found.\n";

    std::cout << "Using aiogram update fallback.\n";


    std::string output;

    int exitCode = -1;


    std::string python = TELEGRAM_VENV + "/bin/python";


    std::string command = shellQuote(python) + " -m pip install --upgrade aiogram";


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Failed to update aiogram.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    if (!output.empty())
    {
        std::cout << output;
    }


    std::cout << "aiogram updated successfully.\n";


    return true;
}


// ============================================================
// BACKUP TELEGRAM CODE
//
// Создаёт бэкап ВСЕГО кода бота. Runtime-данные (telegram.conf,
// verification.json, owner.json, queue/, venv/) намеренно
// исключены, т.к. хранятся напрямую в активной папке.
// ============================================================

bool TelegramBot::backupTelegramCode()
{
    std::cout << "\nCreating complete Telegram bot backup...\n";


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


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create complete Telegram backup.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    std::cout << "Complete Telegram bot backup created:\n" << TELEGRAM_CODE_BACKUP << "\n";


    return true;
}


// ============================================================
// CLEAR TELEGRAM CODE
//
// Удаляет старый код бота, но сохраняет runtime-данные.
// ============================================================

bool TelegramBot::clearTelegramCode()
{
    std::cout << "\nRemoving old Telegram bot code...\n";


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


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot remove old Telegram bot code.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    std::cout << "Old Telegram bot code removed.\n";


    return true;
}


// ============================================================
// RESTORE TELEGRAM CODE
// ============================================================

bool TelegramBot::restoreTelegramCode()
{
    std::cout << "\nRestoring previous Telegram bot version...\n";


    std::string output;

    int exitCode = -1;


    if (!clearTelegramCode())
    {
        std::cout << "Cannot clear failed Telegram version.\n";

        return false;
    }


    std::string command = "test -d " + shellQuote(TELEGRAM_CODE_BACKUP);


    if (!executeRemote(command, output, exitCode, false))
    {
        std::cout << "Telegram backup does not exist.\n";

        return false;
    }


    command =
        "find " +
        shellQuote(TELEGRAM_CODE_BACKUP) +
        " -mindepth 1 -maxdepth 1 "
        "-exec cp -a {} " +
        shellQuote(TELEGRAM_DIR) +
        "/ \\;";


    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot restore Telegram bot backup.\n";

        if (!output.empty())
        {
            std::cout << output << "\n";
        }

        return false;
    }


    setRepositoryPermissions();


    std::cout << "Previous Telegram bot version restored.\n";


    return true;
}


// ============================================================
// SHOW UPDATE LOGS
// ============================================================

void TelegramBot::showUpdateLogs()
{
    std::cout << "\n";

    std::cout << "============================================\n";

    std::cout << "        TELEGRAM SERVICE LOGS\n";

    std::cout << "============================================\n\n";


    std::string logs;

    int exitCode = -1;


    executeRemote(
        "journalctl -u " + TELEGRAM_SERVICE + " -n 50 --no-pager",
        logs,
        exitCode,
        false
    );


    if (!logs.empty())
    {
        std::cout << logs;
    }


    std::cout << "\n";
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
        std::cout << "\n";

        std::cout << "============================================\n";

        std::cout << "             TELEGRAM BOT\n";

        std::cout << "============================================\n\n";


        bool active = serviceIsActive();


        std::cout << "Telegram bot: " << (active ? "ACTIVE" : "INACTIVE") << "\n\n";


        // ====================================================
        // MENU
        // ====================================================

        std::cout << "1. Install / configure bot\n";

        std::cout << "2. Generate verification code\n";

        std::cout << "3. Start bot\n";

        std::cout << "4. Stop bot\n";

        std::cout << "5. Restart bot\n";

        std::cout << "6. Disable automatic startup\n";

        std::cout << "7. Update bot\n";

        std::cout << "8. Check status\n";

        std::cout << "9. Show logs\n";

        std::cout << "10. Remove bot\n";

        std::cout << "0. Back\n\n";


        std::cout << "Select: ";


        std::string choice;


        std::getline(std::cin >> std::ws, choice);


        // ====================================================
        // INSTALL / CONFIGURE  -> install/TelegramBot_Install.cpp
        // ====================================================

        if (choice == "1")
        {
            install();

            continue;
        }


        // ====================================================
        // VERIFICATION -> generate_code/TelegramBot_GenerateCode.cpp
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
                std::cout << "\nTelegram bot is not installed.\n";

                continue;
            }


            if (startService())
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));


                if (serviceIsActive())
                {
                    std::cout << "Telegram bot is ACTIVE.\n";
                }
                else
                {
                    std::cout << "Telegram bot failed to start.\n";
                }
            }


            continue;
        }


        // ====================================================
        // STOP -> stop/TelegramBot_Stop.cpp
        // ====================================================

        if (choice == "4")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";

                continue;
            }


            if (stopService())
            {
                std::cout << "Telegram bot stopped.\n";
            }


            continue;
        }


        // ====================================================
        // RESTART -> restart/TelegramBot_Restart.cpp
        // ====================================================

        if (choice == "5")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";

                continue;
            }


            restartService();


            std::this_thread::sleep_for(std::chrono::seconds(1));


            if (serviceIsActive())
            {
                std::cout << "Telegram bot is ACTIVE.\n";
            }


            continue;
        }


        // ====================================================
        // DISABLE -> autostart_disable/TelegramBot_DisableAutostart.cpp
        // ====================================================

        if (choice == "6")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";

                continue;
            }


            if (disableService())
            {
                std::cout << "Automatic startup disabled.\n";
            }


            continue;
        }


        // ====================================================
        // UPDATE -> update/TelegramBot_Update.cpp
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
                std::cout << "\nTelegram bot is not installed.\n";

                continue;
            }


            std::string output;

            int exitCode = -1;


            executeRemote(
                "systemctl status " + TELEGRAM_SERVICE + " --no-pager",
                output,
                exitCode,
                false
            );


            std::cout << "\n";


            if (!output.empty())
            {
                std::cout << output;
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
                std::cout << "\nTelegram bot is not installed.\n";

                continue;
            }


            std::string output;

            int exitCode = -1;


            executeRemote(
                "journalctl -u " + TELEGRAM_SERVICE + " -n 50 --no-pager",
                output,
                exitCode,
                false
            );


            std::cout << "\n";


            std::cout << "============================================\n";


            std::cout << "             TELEGRAM LOGS\n";


            std::cout << "============================================\n\n";


            if (!output.empty())
            {
                std::cout << output;
            }


            std::cout << "\n";


            continue;
        }


        // ====================================================
        // REMOVE -> remove/TelegramBot_Remove.cpp
        // ====================================================

        if (choice == "10")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";

                continue;
            }


            std::cout << "\nWARNING: This will remove the Telegram bot.\n";


            std::cout << "Continue? (yes/no): ";


            std::string confirmation;


            std::getline(std::cin >> std::ws, confirmation);


            if (confirmation == "yes")
            {
                removeInstallation();
            }
            else
            {
                std::cout << "Cancelled.\n";
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


        std::cout << "Unknown option.\n";
    }
}


// ============================================================
// WEB START
// ============================================================

bool TelegramBot::webStart()
{
    if (!serviceExists())
    {
        return false;
    }

    return startService();
}


// ============================================================
// WEB STATUS
// ============================================================

std::string TelegramBot::webStatus()
{
    bool installed = serviceExists();
    bool active = false;
    bool enabled = false;
    bool config = configExists();
    bool script = checkScript();
    bool requirements = requirementsExists();

    if (installed)
    {
        active = serviceIsActive();

        std::string output;
        int exitCode = -1;

        executeRemote(
            "systemctl is-enabled --quiet " + TELEGRAM_SERVICE,
            output,
            exitCode,
            false
        );

        enabled = (exitCode == 0);
    }

    std::ostringstream json;

    json
        << "{"
        << "\"installed\":"
        << (installed ? "true" : "false")
        << ","
        << "\"active\":"
        << (active ? "true" : "false")
        << ","
        << "\"enabled\":"
        << (enabled ? "true" : "false")
        << ","
        << "\"config\":"
        << (config ? "true" : "false")
        << ","
        << "\"script\":"
        << (script ? "true" : "false")
        << ","
        << "\"requirements\":"
        << (requirements ? "true" : "false")
        << ","
        << "\"service\":\""
        << TELEGRAM_SERVICE
        << "\","
        << "\"directory\":\""
        << TELEGRAM_DIR
        << "\""
        << "}";

    return json.str();
}


// ============================================================
// WEB LOGS
// ============================================================

std::string TelegramBot::webLogs()
{
    std::string logs;
    int exitCode = -1;

    executeRemote(
        "journalctl -u " + TELEGRAM_SERVICE + " -n 100 --no-pager",
        logs,
        exitCode,
        false
    );

    return logs;
}
