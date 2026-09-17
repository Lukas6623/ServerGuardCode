#include <iostream>
#include <fstream>
#include <string>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <libssh2.h>

#include "FileGuard.h"
#include "Security.h"
#include "TelegramBot.h"
#include "SSHHardening.h"
#include "Help.h"

#pragma comment(lib, "ws2_32.lib")


// ============================================================
// CONFIG
// ============================================================

struct Config
{
    std::string host;
    int port = 22;
    std::string username;
    std::string password;
};


// ============================================================
// SAVE CONFIG
// ============================================================

bool saveConfig(const Config& cfg)
{
    std::ofstream file("server.cfg");

    if (!file.is_open())
        return false;

    file << cfg.host << '\n';
    file << cfg.port << '\n';
    file << cfg.username << '\n';
    file << cfg.password << '\n';

    return true;
}


// ============================================================
// LOAD CONFIG
// ============================================================

bool loadConfig(Config& cfg)
{
    std::ifstream file("server.cfg");

    if (!file.is_open())
        return false;

    std::string port;

    if (!std::getline(file, cfg.host))
        return false;

    if (!std::getline(file, port))
        return false;

    if (!std::getline(file, cfg.username))
        return false;

    if (!std::getline(file, cfg.password))
        return false;

    try
    {
        cfg.port = std::stoi(port);
    }
    catch (...)
    {
        return false;
    }

    if (cfg.port <= 0 || cfg.port > 65535)
    {
        return false;
    }

    return true;
}


// ============================================================
// EXECUTE SSH COMMAND
// ============================================================

bool executeCommand(
    LIBSSH2_SESSION* session,
    const std::string& command)
{
    if (!session)
    {
        std::cout
            << "SSH session is not available.\n";

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

    if (libssh2_channel_exec(
        channel,
        command.c_str()) != 0)
    {
        std::cout
            << "Cannot execute command.\n";

        libssh2_channel_free(channel);

        return false;
    }

    char buffer[4096];

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

            std::cout << buffer;
        }
        else if (rc == 0)
        {
            break;
        }
        else
        {
            std::cout
                << "\nError reading server response.\n";

            break;
        }
    }

    libssh2_channel_send_eof(channel);
    libssh2_channel_wait_eof(channel);
    libssh2_channel_wait_closed(channel);

    libssh2_channel_free(channel);

    return true;
}


// ============================================================
// CHANGE DIRECTORY
// ============================================================

bool changeDirectory(
    LIBSSH2_SESSION* session,
    std::string& currentDirectory,
    const std::string& directory)
{
    if (!session)
    {
        std::cout
            << "SSH session is not available.\n";

        return false;
    }

    if (directory.empty())
        return false;

    std::string remoteCommand;

    if (directory == "..")
    {
        remoteCommand =
            "cd \"" +
            currentDirectory +
            "\" && cd .. && pwd";
    }
    else if (directory == "/")
    {
        remoteCommand =
            "cd / && pwd";
    }
    else
    {
        remoteCommand =
            "cd \"" +
            currentDirectory +
            "\" && cd \"" +
            directory +
            "\" && pwd";
    }

    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(session);

    if (!channel)
    {
        std::cout
            << "Cannot open SSH channel.\n";

        return false;
    }

    if (libssh2_channel_exec(
        channel,
        remoteCommand.c_str()) != 0)
    {
        std::cout
            << "Cannot change directory.\n";

        libssh2_channel_free(channel);

        return false;
    }

    char buffer[4096];

    std::string result;

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

    libssh2_channel_send_eof(channel);
    libssh2_channel_wait_eof(channel);
    libssh2_channel_wait_closed(channel);

    libssh2_channel_free(channel);

    while (!result.empty() &&
        (result.back() == '\n' ||
            result.back() == '\r'))
    {
        result.pop_back();
    }

    if (result.empty())
    {
        std::cout
            << "Directory does not exist.\n";

        return false;
    }

    currentDirectory = result;

    return true;
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    Config cfg;


    // ========================================================
    // HEADER
    // ========================================================

    std::cout
        << "=============================\n";

    std::cout
        << "        ServerGuard\n";

    std::cout
        << "=============================\n\n";


    // ========================================================
    // LOAD CONFIG
    // ========================================================

    if (!loadConfig(cfg))
    {
        std::cout
            << "First launch.\n\n";

        std::cout
            << "Server IP: ";

        std::cin
            >> cfg.host;

        std::cout
            << "SSH port [22]: ";

        std::string portInput;

        std::cin
            >> portInput;

        if (portInput.empty())
        {
            cfg.port = 22;
        }
        else
        {
            try
            {
                cfg.port = std::stoi(portInput);
            }
            catch (...)
            {
                std::cout
                    << "Invalid port. Using 22.\n";

                cfg.port = 22;
            }
        }

        if (cfg.port <= 0 || cfg.port > 65535)
        {
            std::cout
                << "Invalid port. Using 22.\n";

            cfg.port = 22;
        }

        std::cout
            << "Username: ";

        std::cin
            >> cfg.username;

        std::cout
            << "Password: ";

        std::cin
            >> cfg.password;

        if (!saveConfig(cfg))
        {
            std::cout
                << "\nWarning: cannot save server.cfg\n";
        }
        else
        {
            std::cout
                << "\nConnection data saved.\n";
        }
    }
    else
    {
        std::cout
            << "Saved connection found.\n";

        std::cout
            << "Server: "
            << cfg.host
            << ":"
            << cfg.port
            << "\n";

        std::cout
            << "User: "
            << cfg.username
            << "\n";
    }


    // ========================================================
    // WINDOWS SOCKET
    // ========================================================

    WSADATA wsadata;

    if (WSAStartup(
        MAKEWORD(2, 2),
        &wsadata) != 0)
    {
        std::cout
            << "WSAStartup failed.\n";

        return 1;
    }


    // ========================================================
    // LIBSSH2 INIT
    // ========================================================

    if (libssh2_init(0) != 0)
    {
        std::cout
            << "libssh2 initialization failed.\n";

        WSACleanup();

        return 1;
    }


    // ========================================================
    // SOCKET
    // ========================================================

    SOCKET sock =
        socket(
            AF_INET,
            SOCK_STREAM,
            0);

    if (sock == INVALID_SOCKET)
    {
        std::cout
            << "Cannot create socket.\n";

        libssh2_exit();
        WSACleanup();

        return 1;
    }


    // ========================================================
    // SERVER ADDRESS
    // ========================================================

    sockaddr_in sin{};

    sin.sin_family = AF_INET;

    sin.sin_port =
        htons(
            static_cast<u_short>(
                cfg.port));

    if (inet_pton(
        AF_INET,
        cfg.host.c_str(),
        &sin.sin_addr) <= 0)
    {
        std::cout
            << "Invalid server IP.\n";

        closesocket(sock);

        libssh2_exit();
        WSACleanup();

        return 1;
    }


    // ========================================================
    // TCP CONNECT
    // ========================================================

    std::cout
        << "\nConnecting to "
        << cfg.host
        << ":"
        << cfg.port
        << "...\n";

    if (connect(
        sock,
        reinterpret_cast<sockaddr*>(&sin),
        sizeof(sin)) != 0)
    {
        std::cout
            << "Connection failed.\n";

        closesocket(sock);

        libssh2_exit();
        WSACleanup();

        return 1;
    }

    std::cout
        << "TCP connection established.\n";


    // ========================================================
    // SSH SESSION
    // ========================================================

    LIBSSH2_SESSION* session =
        libssh2_session_init();

    if (!session)
    {
        std::cout
            << "Cannot create SSH session.\n";

        closesocket(sock);

        libssh2_exit();
        WSACleanup();

        return 1;
    }


    // ========================================================
    // SSH HANDSHAKE
    // ========================================================

    if (libssh2_session_handshake(
        session,
        sock) != 0)
    {
        std::cout
            << "SSH handshake failed.\n";

        libssh2_session_free(session);

        closesocket(sock);

        libssh2_exit();
        WSACleanup();

        return 1;
    }

    std::cout
        << "SSH connection established.\n";


    // ========================================================
    // AUTHENTICATION
    // ========================================================

    if (libssh2_userauth_password(
        session,
        cfg.username.c_str(),
        cfg.password.c_str()) != 0)
    {
        std::cout
            << "Authentication failed.\n";

        libssh2_session_disconnect(
            session,
            "Authentication failed");

        libssh2_session_free(session);

        closesocket(sock);

        libssh2_exit();
        WSACleanup();

        return 1;
    }

    std::cout
        << "Authenticated successfully.\n";


    // ========================================================
    // SECURITY
    // ========================================================

    Security security(
        session,
        cfg.password);


    // ========================================================
    // TELEGRAM BOT
    // ========================================================

    TelegramBot telegramBot(
        session,
        cfg.password);


    // ========================================================
    // FILE GUARD
    // ========================================================

    FileGuard fileGuard(
        session,
        cfg.password);


    // ========================================================
    // SSH HARDENING
    // ========================================================

    SSHHardening sshHardening(
        session,
        cfg.password);


    // ========================================================
    // TERMINAL
    // ========================================================

    std::cout
        << "\n";

    std::cout
        << "ServerGuard terminal\n";

    std::cout
        << "Type 'help' to show all commands and modules.\n";

    std::cout
        << "Type 'ls' to list files.\n";

    std::cout
        << "Type 'pwd' to show current directory.\n";

    std::cout
        << "Type 'cd <directory>' to change directory.\n";

    std::cout
        << "Type 'security' to open security menu.\n";

    std::cout
        << "Type 'telegram' to open Telegram Bot menu.\n";

    std::cout
        << "Type 'hardening' to open SSH hardening menu.\n";

    std::cout
        << "Type 'fileguard' to open FileGuard menu.\n";

    std::cout
        << "Type 'exit' to close connection.\n";

    std::cout
        << "\n";

    std::cout
        << "Type 'help' for detailed information.\n";

    std::cout
        << "\n";


    // ========================================================
    // CURRENT DIRECTORY
    // ========================================================

    std::string currentDirectory = ".";


    // ========================================================
    // COMMAND LOOP
    // ========================================================

    while (true)
    {
        std::cout
            << cfg.username
            << "@"
            << cfg.host
            << ":"
            << currentDirectory
            << "$ ";

        std::string command;

        std::getline(
            std::cin >> std::ws,
            command);


        // ====================================================
        // EXIT
        // ====================================================

        if (command == "exit")
        {
            break;
        }


        // ====================================================
        // HELP
        // ====================================================

        if (command == "help")
        {
            showHelp();


            continue;
        }


        // ====================================================
        // SECURITY
        // ====================================================

        if (command == "security")
        {
            security.menu();

            continue;
        }


        // ====================================================
        // TELEGRAM BOT
        // ====================================================

        if (command == "telegram")
        {
            telegramBot.menu();

            continue;
        }


        // ====================================================
        // SSH HARDENING
        // ====================================================

        if (command == "hardening")
        {
            sshHardening.menu();

            continue;
        }


        // ====================================================
        // FILE GUARD
        // ====================================================

        if (command == "fileguard")
        {
            fileGuard.menu();

            continue;
        }


        // ====================================================
        // LS
        // ====================================================

        if (command == "ls")
        {
            std::string remoteCommand =
                "cd \"" +
                currentDirectory +
                "\" && ls";

            executeCommand(
                session,
                remoteCommand);

            continue;
        }


        // ====================================================
        // PWD
        // ====================================================

        if (command == "pwd")
        {
            std::string remoteCommand =
                "cd \"" +
                currentDirectory +
                "\" && pwd";

            executeCommand(
                session,
                remoteCommand);

            continue;
        }


        // ====================================================
        // CD
        // ====================================================

        if (command.rfind("cd ", 0) == 0)
        {
            std::string directory =
                command.substr(3);

            if (directory.empty())
            {
                continue;
            }

            changeDirectory(
                session,
                currentDirectory,
                directory);

            continue;
        }


        // ====================================================
        // UNKNOWN COMMAND
        // ====================================================

        std::cout
            << "Unknown command: "
            << command
            << "\n";

        std::cout
            << "Available commands: "
            << "help, ls, pwd, cd, security, telegram, "
            << "hardening, fileguard, exit\n";
    }


    // ========================================================
    // DISCONNECT
    // ========================================================

    std::cout
        << "\nDisconnecting...\n";

    libssh2_session_disconnect(
        session,
        "Normal shutdown");

    libssh2_session_free(session);

    closesocket(sock);

    libssh2_exit();

    WSACleanup();

    std::cout
        << "Disconnected.\n";

    return 0;
}