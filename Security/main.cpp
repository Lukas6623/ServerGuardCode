#define NOMINMAX

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <limits>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>

#include <libssh2.h>

#include "FileGuard.h"
#include "Security.h"
#include "TelegramBot.h"
#include "SSHHardening.h"
#include "SSHKeyGuard.h"
#include "Help.h"
#include "WebServer.h"
#include "Web.h"
#include "Nano.h"
#include "Firewall.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")



enum class AuthMethod
{
    Password,
    PublicKey,
    Agent,
    Interactive
};

static std::string authMethodToString(AuthMethod m)
{
    switch (m)
    {
    case AuthMethod::PublicKey:   return "key";
    case AuthMethod::Agent:       return "agent";
    case AuthMethod::Interactive: return "interactive";
    default:                      return "password";
    }
}

static AuthMethod authMethodFromString(const std::string& s)
{
    if (s == "key")         return AuthMethod::PublicKey;
    if (s == "agent")       return AuthMethod::Agent;
    if (s == "interactive") return AuthMethod::Interactive;
    return AuthMethod::Password;
}

static std::string authMethodTitle(AuthMethod m)
{
    switch (m)
    {
    case AuthMethod::PublicKey:   return "Private key";
    case AuthMethod::Agent:       return "SSH agent";
    case AuthMethod::Interactive: return "Keyboard-interactive";
    default:                      return "Password";
    }
}

static int authMethodNumber(AuthMethod m)
{
    switch (m)
    {
    case AuthMethod::PublicKey:   return 2;
    case AuthMethod::Agent:       return 3;
    case AuthMethod::Interactive: return 4;
    default:                      return 1;
    }
}


// ============================================================
//  Server profile
// ============================================================

struct Config
{
    std::string name;           // display name in the server list

    std::string host;
    int port = 22;
    std::string username;

    std::string password;       // login / sudo password (memory)
    bool savePassword = false;  // store password (DPAPI-encrypted)

    AuthMethod auth = AuthMethod::Password;

    std::string keyPath;
    std::string passphrase;     // never saved
};


// ============================================================
//  Helpers
// ============================================================

static std::string trim(const std::string& s)
{
    size_t a = 0;
    size_t b = s.size();

    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;

    return s.substr(a, b - a);
}

static std::string toLower(std::string s)
{
    std::transform(
        s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
    );

    return s;
}

static std::string readLine(const std::string& prompt, const std::string& def = "")
{
    std::cout << prompt;

    std::string line;

    if (!std::getline(std::cin, line))
    {
        return def;
    }

    line = trim(line);

    return line.empty() ? def : line;
}

static std::string readSecret(const std::string& prompt)
{
    std::cout << prompt;

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

    DWORD mode = 0;

    bool hidden = (GetConsoleMode(hIn, &mode) != 0);

    if (hidden)
    {
        SetConsoleMode(hIn, mode & ~ENABLE_ECHO_INPUT);
    }

    std::string line;
    std::getline(std::cin, line);

    if (hidden)
    {
        SetConsoleMode(hIn, mode);
    }

    std::cout << "\n";

    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
    {
        line.pop_back();
    }

    return line;
}

static bool askYesNo(const std::string& prompt, bool def)
{
    std::string a =
        toLower(readLine(prompt + (def ? " (Y/n): " : " (y/N): "), def ? "y" : "n"));

    return a == "y" || a == "yes" || a == "д" || a == "да";
}

static bool fileExists(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);

    return f.good();
}

static std::string stripQuotes(std::string s)
{
    s = trim(s);

    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
    {
        s = s.substr(1, s.size() - 2);
    }

    return s;
}

static std::string defaultKeyPath()
{
    char* home = nullptr;
    size_t len = 0;

    if (_dupenv_s(&home, &len, "USERPROFILE") != 0 || !home)
    {
        return "";
    }

    std::string base = std::string(home) + "\\.ssh\\";

    free(home);

    const char* names[] = { "id_ed25519", "id_rsa", "id_ecdsa" };

    for (const char* name : names)
    {
        if (fileExists(base + name))
        {
            return base + name;
        }
    }

    return base + "id_ed25519";
}

static std::string toHex(const unsigned char* data, size_t len)
{
    static const char* digits = "0123456789abcdef";

    std::string out;

    for (size_t i = 0; i < len; i++)
    {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0x0F];
    }

    return out;
}

static bool fromHex(const std::string& hex, std::string& out)
{
    out.clear();

    if (hex.size() % 2 != 0)
        return false;

    auto val = [](char c) -> int
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        int hi = val(hex[i]);
        int lo = val(hex[i + 1]);

        if (hi < 0 || lo < 0)
            return false;

        out += static_cast<char>((hi << 4) | lo);
    }

    return true;
}


// ============================================================
//  Password protection (Windows DPAPI: bound to current user)
// ============================================================

static std::string protectSecret(const std::string& plain)
{
    if (plain.empty())
        return "";

    DATA_BLOB in;
    in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()));
    in.cbData = static_cast<DWORD>(plain.size());

    DATA_BLOB out{};

    if (!CryptProtectData(&in, L"ServerGuard", nullptr, nullptr,
        nullptr, 0, &out))
    {
        return "";
    }

    std::string hex = toHex(out.pbData, out.cbData);

    LocalFree(out.pbData);

    return hex;
}

static std::string unprotectSecret(const std::string& hex)
{
    if (hex.empty())
        return "";

    std::string raw;

    if (!fromHex(hex, raw) || raw.empty())
        return "";

    DATA_BLOB in;
    in.pbData = reinterpret_cast<BYTE*>(raw.data());
    in.cbData = static_cast<DWORD>(raw.size());

    DATA_BLOB out{};

    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr,
        nullptr, 0, &out))
    {
        return "";
    }

    std::string plain(reinterpret_cast<char*>(out.pbData), out.cbData);

    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);

    return plain;
}


// ============================================================
//  Profile storage (servers.cfg, tab separated)
// ============================================================

static const char* PROFILES_FILE = "servers.cfg";
static const char* LEGACY_FILE = "server.cfg";

static std::string cleanField(std::string s)
{
    for (char& c : s)
    {
        if (c == '\t' || c == '\n' || c == '\r')
            c = ' ';
    }

    return s;
}

static bool saveProfiles(const std::vector<Config>& list)
{
    std::ofstream file(PROFILES_FILE, std::ios::trunc);

    if (!file.is_open())
        return false;

    for (const Config& c : list)
    {
        file << cleanField(c.name) << '\t'
            << cleanField(c.host) << '\t'
            << c.port << '\t'
            << cleanField(c.username) << '\t'
            << authMethodToString(c.auth) << '\t'
            << cleanField(c.keyPath) << '\t'
            << (c.savePassword ? protectSecret(c.password) : "")
            << '\n';
    }

    return true;
}

static std::vector<Config> loadProfiles()
{
    std::vector<Config> list;

    std::ifstream file(PROFILES_FILE);

    if (!file.is_open())
        return list;

    std::string line;

    while (std::getline(file, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();

        if (line.empty())
            continue;

        std::vector<std::string> f;
        std::stringstream ss(line);
        std::string part;

        while (std::getline(ss, part, '\t'))
            f.push_back(part);

        if (!line.empty() && line.back() == '\t')
            f.push_back("");

        if (f.size() < 6)
            continue;

        Config c;

        c.name = f[0];
        c.host = f[1];

        try { c.port = std::stoi(f[2]); }
        catch (...) { continue; }

        if (c.port <= 0 || c.port > 65535)
            continue;

        c.username = f[3];
        c.auth = authMethodFromString(f[4]);
        c.keyPath = f[5];

        if (f.size() >= 7 && !f[6].empty())
        {
            c.password = unprotectSecret(f[6]);
            c.savePassword = !c.password.empty();
        }

        if (c.name.empty())
            c.name = c.host;

        list.push_back(c);
    }

    return list;
}

// Import of the old single-server file (server.cfg)
static void migrateLegacyConfig()
{
    if (fileExists(PROFILES_FILE) || !fileExists(LEGACY_FILE))
        return;

    std::ifstream file(LEGACY_FILE);

    Config c;
    std::string port, method, keyPath;

    if (!std::getline(file, c.host) ||
        !std::getline(file, port) ||
        !std::getline(file, c.username) ||
        !std::getline(file, c.password))
    {
        return;
    }

    try { c.port = std::stoi(port); }
    catch (...) { return; }

    if (c.port <= 0 || c.port > 65535)
        return;

    if (std::getline(file, method))
        c.auth = authMethodFromString(trim(method));

    if (std::getline(file, keyPath))
        c.keyPath = trim(keyPath);

    c.host = trim(c.host);
    c.username = trim(c.username);
    c.name = c.host;
    c.savePassword = !c.password.empty();

    file.close();

    std::vector<Config> list{ c };

    if (!saveProfiles(list))
        return;

    std::string backup = std::string(LEGACY_FILE) + ".bak";

    std::remove(backup.c_str());
    std::rename(LEGACY_FILE, backup.c_str());

    std::cout << "Old server.cfg imported as a profile and renamed to "
        << backup << ".\n"
        << "It contains a plain-text password - delete it when you "
        "no longer need it.\n\n";
}


// ============================================================
//  Profile editor
// ============================================================

static bool editProfile(Config& cfg, bool isNew)
{
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << (isNew ? "          ADD NEW SERVER\n"
        : "          EDIT SERVER\n");
    std::cout << "========================================\n\n";

    std::string oldHost = cfg.host;

    // host
    while (true)
    {
        cfg.host = readLine(
            isNew || cfg.host.empty() ? "Server IP: "
            : "Server IP [" + cfg.host + "]: ",
            cfg.host);

        if (!cfg.host.empty())
            break;

        std::cout << "Server IP cannot be empty.\n";

        if (!std::cin.good())
            return false;
    }

    // port
    {
        std::string def = std::to_string(cfg.port);
        std::string input = readLine("SSH port [" + def + "]: ", def);

        try { cfg.port = std::stoi(input); }
        catch (...)
        {
            std::cout << "Invalid port. Using 22.\n";
            cfg.port = 22;
        }

        if (cfg.port <= 0 || cfg.port > 65535)
        {
            std::cout << "Invalid port. Using 22.\n";
            cfg.port = 22;
        }
    }

    // username
    while (true)
    {
        cfg.username = readLine(
            cfg.username.empty() ? "Username: "
            : "Username [" + cfg.username + "]: ",
            cfg.username);

        if (!cfg.username.empty())
            break;

        std::cout << "Username cannot be empty.\n";

        if (!std::cin.good())
            return false;
    }

    // auth method
    std::cout << "\nAuthentication method:\n";
    std::cout << "1. Password\n";
    std::cout << "2. Private key file (id_ed25519 / id_rsa / .pem)\n";
    std::cout << "3. SSH agent (Pageant / Windows OpenSSH agent)\n";
    std::cout << "4. Keyboard-interactive (PAM / 2FA)\n\n";

    {
        std::string def = std::to_string(authMethodNumber(cfg.auth));

        while (true)
        {
            std::string choice = readLine("Select [" + def + "]: ", def);

            if (choice == "1") { cfg.auth = AuthMethod::Password;    break; }
            if (choice == "2") { cfg.auth = AuthMethod::PublicKey;   break; }
            if (choice == "3") { cfg.auth = AuthMethod::Agent;       break; }
            if (choice == "4") { cfg.auth = AuthMethod::Interactive; break; }

            std::cout << "Invalid option. Please select 1, 2, 3 or 4.\n";

            if (!std::cin.good())
                return false;
        }
    }

    cfg.password.clear();
    cfg.passphrase.clear();

    switch (cfg.auth)
    {
    case AuthMethod::Password:
    case AuthMethod::Interactive:

        cfg.keyPath.clear();
        cfg.password = readSecret("Password (Enter = ask on every connect): ");
        break;

    case AuthMethod::PublicKey:
    {
        std::string def = cfg.keyPath.empty() ? defaultKeyPath() : cfg.keyPath;

        std::string prompt = "Private key path";

        if (!def.empty())
            prompt += " [" + def + "]";

        prompt += ": ";

        cfg.keyPath = stripQuotes(readLine(prompt, def));

        cfg.password = readSecret(
            "Sudo password for server modules "
            "(Enter = ask on every connect): ");

        break;
    }

    case AuthMethod::Agent:

        cfg.keyPath.clear();
        cfg.password = readSecret(
            "Sudo password for server modules "
            "(Enter = ask on every connect): ");
        break;
    }

    cfg.savePassword = false;

    if (!cfg.password.empty())
    {
        cfg.savePassword = askYesNo(
            "Save password on this PC (encrypted with Windows DPAPI)?",
            false);
    }

    // display name
    {
        std::string def = cfg.name;

        if (def.empty() || (!isNew && def == oldHost))
            def = cfg.host;

        cfg.name = cleanField(readLine("Server name [" + def + "]: ", def));
    }

    return true;
}


// ============================================================
//  Host key verification
// ============================================================

bool verifyHostKey(LIBSSH2_SESSION* session, const Config& cfg)
{
    std::string algo = "SHA256";

    size_t hashLen = 32;

    const char* raw =
        libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);

    if (!raw)
    {
        algo = "SHA1";
        hashLen = 20;

        raw = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    }

    if (!raw)
    {
        std::cout
            << "Warning: cannot read server host key fingerprint.\n";

        return true;
    }

    std::string fingerprint =
        algo + ":" +
        toHex(reinterpret_cast<const unsigned char*>(raw), hashLen);

    std::string id =
        cfg.host + ":" + std::to_string(cfg.port);

    std::vector<std::string> lines;

    std::string storedFingerprint;
    bool found = false;

    {
        std::ifstream in("known_hosts.txt");

        std::string line;

        while (std::getline(in, line))
        {
            line = trim(line);

            if (line.empty())
                continue;

            size_t space = line.find(' ');

            if (space != std::string::npos && line.substr(0, space) == id)
            {
                found = true;
                storedFingerprint = trim(line.substr(space + 1));
            }

            lines.push_back(line);
        }
    }

    if (found && storedFingerprint == fingerprint)
    {
        std::cout << "Host key verified.\n";

        return true;
    }

    if (found)
    {
        std::cout << "\n########################################\n";
        std::cout << "  WARNING: SERVER HOST KEY HAS CHANGED!\n";
        std::cout << "########################################\n";
        std::cout << "Someone may be intercepting the connection "
            "(man-in-the-middle),\n";
        std::cout << "or the server was reinstalled.\n\n";
        std::cout << "Stored: " << storedFingerprint << "\n";
        std::cout << "Now:    " << fingerprint << "\n\n";

        std::string answer =
            readLine("Trust the new key and replace the stored one? (yes/no): ", "no");

        if (toLower(answer) != "yes")
        {
            return false;
        }

        std::ofstream out("known_hosts.txt", std::ios::trunc);

        for (const std::string& line : lines)
        {
            size_t space = line.find(' ');

            if (space != std::string::npos && line.substr(0, space) == id)
            {
                out << id << ' ' << fingerprint << '\n';
            }
            else
            {
                out << line << '\n';
            }
        }

        return true;
    }

    std::cout << "\nFirst connection to " << id << ".\n";
    std::cout << "Server host key fingerprint:\n";
    std::cout << fingerprint << "\n\n";

    std::string answer =
        readLine("Trust this server and continue? (yes/no): ", "no");

    if (toLower(answer) != "yes")
    {
        return false;
    }

    std::ofstream out("known_hosts.txt", std::ios::app);

    out << id << ' ' << fingerprint << '\n';

    return true;
}


// ============================================================
//  Authentication
// ============================================================

struct KbdContext
{
    const std::string* password = nullptr;

    bool passwordUsed = false;
};

static void kbdCallback(
    const char* name,
    int name_len,
    const char* instruction,
    int instruction_len,
    int num_prompts,
    const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
    LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
    void** abstract)
{
    KbdContext* ctx =
        abstract ? static_cast<KbdContext*>(*abstract) : nullptr;

    if (name && name_len > 0)
    {
        std::cout << "\n" << std::string(name, name_len) << "\n";
    }

    if (instruction && instruction_len > 0)
    {
        std::cout << std::string(instruction, instruction_len) << "\n";
    }

    for (int i = 0; i < num_prompts; i++)
    {
        std::string prompt(
            reinterpret_cast<const char*>(prompts[i].text),
            prompts[i].length
        );

        std::string answer;

        bool isPassword =
            toLower(prompt).find("password") != std::string::npos;

        if (
            isPassword &&
            ctx &&
            ctx->password &&
            !ctx->password->empty() &&
            !ctx->passwordUsed)
        {
            answer = *ctx->password;

            ctx->passwordUsed = true;
        }
        else
        {
            if (prompts[i].echo)
                answer = readLine(prompt);
            else
                answer = readSecret(prompt);
        }

        responses[i].text = _strdup(answer.c_str());

        responses[i].length =
            static_cast<unsigned int>(answer.size());
    }
}

static void printSessionError(LIBSSH2_SESSION* session)
{
    char* message = nullptr;

    int length = 0;

    int code =
        libssh2_session_last_error(session, &message, &length, 0);

    std::cout
        << "libssh2 error "
        << code
        << ": "
        << (message ? message : "unknown")
        << "\n";
}

static bool authPassword(LIBSSH2_SESSION* session, const Config& cfg)
{
    return libssh2_userauth_password(
        session,
        cfg.username.c_str(),
        cfg.password.c_str()
    ) == 0;
}

static bool authKeyboardInteractive(
    LIBSSH2_SESSION* session,
    const Config& cfg)
{
    KbdContext ctx;

    ctx.password = &cfg.password;

    void** abstract = libssh2_session_abstract(session);

    void* previous = abstract ? *abstract : nullptr;

    if (abstract)
        *abstract = &ctx;

    int rc =
        libssh2_userauth_keyboard_interactive(
            session,
            cfg.username.c_str(),
            &kbdCallback
        );

    if (abstract)
        *abstract = previous;

    return rc == 0;
}

static bool authPublicKey(LIBSSH2_SESSION* session, const Config& cfg)
{
    if (cfg.keyPath.empty())
    {
        std::cout << "Private key path is not set.\n";

        return false;
    }

    if (!fileExists(cfg.keyPath))
    {
        std::cout
            << "Private key file not found:\n"
            << cfg.keyPath
            << "\n";

        return false;
    }

    std::string pubPath = cfg.keyPath + ".pub";

    const char* pub =
        fileExists(pubPath) ? pubPath.c_str() : nullptr;

    int rc =
        libssh2_userauth_publickey_fromfile(
            session,
            cfg.username.c_str(),
            pub,
            cfg.keyPath.c_str(),
            cfg.passphrase.empty() ? nullptr : cfg.passphrase.c_str()
        );

    if (rc == 0)
        return true;

    printSessionError(session);

    if (rc == LIBSSH2_ERROR_FILE)
    {
        std::cout
            << "Hint: the key file could not be read. Check the "
            "passphrase, or\n"
            "convert the key to PEM format:\n"
            "  ssh-keygen -p -m PEM -f <keyfile>\n"
            "(some libssh2 builds do not support the new "
            "OpenSSH key format)\n";
    }
    else if (rc == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED)
    {
        std::cout
            << "The server rejected this key. Make sure the public "
            "key is in\n"
            "~/.ssh/authorized_keys of the user on the server.\n";
    }

    return false;
}

static bool authAgent(LIBSSH2_SESSION* session, const Config& cfg)
{
    LIBSSH2_AGENT* agent = libssh2_agent_init(session);

    if (!agent)
    {
        std::cout << "Cannot initialize SSH agent support.\n";

        return false;
    }

    if (libssh2_agent_connect(agent) != 0)
    {
        std::cout
            << "Cannot connect to SSH agent. Start Pageant or the "
            "'OpenSSH Authentication Agent' service.\n";

        libssh2_agent_free(agent);

        return false;
    }

    if (libssh2_agent_list_identities(agent) != 0)
    {
        std::cout << "Cannot list keys from SSH agent.\n";

        libssh2_agent_disconnect(agent);
        libssh2_agent_free(agent);

        return false;
    }

    libssh2_agent_publickey* identity = nullptr;
    libssh2_agent_publickey* previous = nullptr;

    bool authenticated = false;
    bool anyIdentity = false;

    while (true)
    {
        int rc =
            libssh2_agent_get_identity(agent, &identity, previous);

        if (rc == 1)
            break;

        if (rc < 0)
        {
            std::cout << "Cannot read key from SSH agent.\n";
            break;
        }

        anyIdentity = true;

        if (
            libssh2_agent_userauth(
                agent,
                cfg.username.c_str(),
                identity) == 0)
        {
            std::cout
                << "Agent key accepted: "
                << (identity->comment ? identity->comment : "(no comment)")
                << "\n";

            authenticated = true;

            break;
        }

        std::cout
            << "Agent key rejected: "
            << (identity->comment ? identity->comment : "(no comment)")
            << "\n";

        previous = identity;
    }

    if (!anyIdentity)
    {
        std::cout << "SSH agent has no keys loaded.\n";
    }

    libssh2_agent_disconnect(agent);
    libssh2_agent_free(agent);

    return authenticated;
}

bool authenticate(LIBSSH2_SESSION* session, const Config& cfg)
{
    char* list =
        libssh2_userauth_list(
            session,
            cfg.username.c_str(),
            static_cast<unsigned int>(cfg.username.size())
        );

    if (!list)
    {
        if (libssh2_userauth_authenticated(session))
        {
            std::cout << "Server accepted the connection "
                "without authentication.\n";

            return true;
        }
    }

    std::string methods = list ? list : "";

    bool unknown = methods.empty();

    auto supports = [&](const char* method)
        {
            return unknown || methods.find(method) != std::string::npos;
        };

    if (!unknown)
    {
        std::cout
            << "Server authentication methods: "
            << methods
            << "\n";
    }

    std::cout
        << "Authenticating ("
        << authMethodTitle(cfg.auth)
        << ")...\n";

    switch (cfg.auth)
    {
    case AuthMethod::Password:

        if (supports("password"))
        {
            if (authPassword(session, cfg))
                return true;
        }

        if (supports("keyboard-interactive"))
        {
            std::cout
                << "Trying keyboard-interactive "
                "with the same password...\n";

            if (authKeyboardInteractive(session, cfg))
                return true;
        }

        if (!supports("password") && !supports("keyboard-interactive"))
        {
            std::cout
                << "The server does not allow password login.\n"
                "Choose 'Private key' or 'SSH agent'.\n";
        }

        return false;

    case AuthMethod::PublicKey:

        if (!supports("publickey"))
        {
            std::cout
                << "The server does not allow public key login.\n";

            return false;
        }

        return authPublicKey(session, cfg);

    case AuthMethod::Agent:

        if (!supports("publickey"))
        {
            std::cout
                << "The server does not allow public key login.\n";

            return false;
        }

        return authAgent(session, cfg);

    case AuthMethod::Interactive:

        if (!supports("keyboard-interactive"))
        {
            std::cout
                << "The server does not allow "
                "keyboard-interactive login.\n";

            return false;
        }

        return authKeyboardInteractive(session, cfg);
    }

    return false;
}


// ============================================================
//  Connection
// ============================================================

static void closeConnection(
    LIBSSH2_SESSION*& session,
    SOCKET& sock,
    const char* reason,
    bool sendDisconnect)
{
    if (session)
    {
        if (sendDisconnect)
        {
            libssh2_session_disconnect(session, reason);
        }

        libssh2_session_free(session);

        session = nullptr;
    }

    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);

        sock = INVALID_SOCKET;
    }
}

bool openConnection(
    Config& cfg,
    SOCKET& sock,
    LIBSSH2_SESSION*& session)
{
    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock == INVALID_SOCKET)
    {
        std::cout << "\nCannot create socket.\n";

        return false;
    }

    sockaddr_in sin{};

    sin.sin_family = AF_INET;

    sin.sin_port =
        htons(static_cast<u_short>(cfg.port));

    if (inet_pton(AF_INET, cfg.host.c_str(), &sin.sin_addr) <= 0)
    {
        std::cout << "\nInvalid server IP.\n";

        closeConnection(session, sock, "", false);

        return false;
    }

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
            << "Connection failed (WSA error "
            << WSAGetLastError()
            << ").\n";

        closeConnection(session, sock, "", false);

        return false;
    }

    std::cout << "TCP connection established.\n";

    session = libssh2_session_init();

    if (!session)
    {
        std::cout << "Cannot create SSH session.\n";

        closeConnection(session, sock, "", false);

        return false;
    }

    libssh2_session_set_timeout(session, 30000);

    int rc = libssh2_session_handshake(session, sock);

    if (rc != 0)
    {
        std::cout
            << "SSH handshake failed (error "
            << rc
            << ").\n";

        closeConnection(session, sock, "", false);

        return false;
    }

    std::cout << "SSH connection established.\n";

    if (!verifyHostKey(session, cfg))
    {
        std::cout << "\nHost key is not trusted. Connection aborted.\n";

        closeConnection(session, sock, "Host key rejected", true);

        return false;
    }

    if (!authenticate(session, cfg))
    {
        std::cout << "\nAuthentication failed.\n";

        closeConnection(session, sock, "Authentication failed", true);

        return false;
    }

    std::cout << "Authenticated successfully.\n";

    return true;
}


// ============================================================
//  Remote commands
// ============================================================

bool executeCommand(
    LIBSSH2_SESSION* session,
    const std::string& command)
{
    if (!session)
    {
        std::cout << "SSH session is not available.\n";

        return false;
    }

    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(session);

    if (!channel)
    {
        std::cout << "Cannot open SSH channel.\n";

        return false;
    }

    if (libssh2_channel_exec(channel, command.c_str()) != 0)
    {
        std::cout << "Cannot execute command.\n";

        libssh2_channel_free(channel);

        return false;
    }

    char buffer[4096];

    while (true)
    {
        int rc =
            libssh2_channel_read(channel, buffer, sizeof(buffer) - 1);

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
            std::cout << "\nError reading server response.\n";

            break;
        }
    }

    libssh2_channel_send_eof(channel);
    libssh2_channel_wait_eof(channel);
    libssh2_channel_wait_closed(channel);

    libssh2_channel_free(channel);

    return true;
}

bool changeDirectory(
    LIBSSH2_SESSION* session,
    std::string& currentDirectory,
    const std::string& directory)
{
    if (!session)
    {
        std::cout << "SSH session is not available.\n";

        return false;
    }

    if (directory.empty())
        return false;

    std::string remoteCommand;

    if (directory == "..")
    {
        remoteCommand =
            "cd \"" + currentDirectory + "\" && cd .. && pwd";
    }
    else if (directory == "/")
    {
        remoteCommand = "cd / && pwd";
    }
    else
    {
        remoteCommand =
            "cd \"" + currentDirectory +
            "\" && cd \"" + directory + "\" && pwd";
    }

    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(session);

    if (!channel)
    {
        std::cout << "Cannot open SSH channel.\n";

        return false;
    }

    if (libssh2_channel_exec(channel, remoteCommand.c_str()) != 0)
    {
        std::cout << "Cannot change directory.\n";

        libssh2_channel_free(channel);

        return false;
    }

    char buffer[4096];

    std::string result;

    while (true)
    {
        int rc =
            libssh2_channel_read(channel, buffer, sizeof(buffer) - 1);

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

    while (
        !result.empty() &&
        (result.back() == '\n' || result.back() == '\r'))
    {
        result.pop_back();
    }

    if (result.empty())
    {
        std::cout << "Directory does not exist.\n";

        return false;
    }

    currentDirectory = result;

    return true;
}


// ============================================================
//  Server terminal
// ============================================================

void runServerTerminal(
    LIBSSH2_SESSION* session,
    const Config& cfg,
    TelegramBot* telegramBot,
    SSHKeyGuard* sshKeyGuard,
    Security* security,
    SSHHardening* sshHardening,
    WebServer* webServer,
    FirewallManager* firewall)
{
    FileGuard fileGuard(session, cfg.password);

    std::cout << "\n";
    std::cout << "ServerGuard terminal - " << cfg.name << "\n";
    std::cout << "Type 'help' to show all commands and modules.\n";
    std::cout << "Type 'ls' to list files.\n";
    std::cout << "Type 'pwd' to show current directory.\n";
    std::cout << "Type 'cd <directory>' to change directory.\n";
    std::cout << "Type 'nano <file>' to edit a file on the server.\n";
    std::cout << "Type 'security' to open security menu.\n";
    std::cout << "Type 'telegram' to open Telegram Bot menu.\n";
    std::cout << "Type 'hardening' to open SSH hardening menu.\n";
    std::cout << "Type 'sshkeys' to open SSH Key Guard menu.\n";
    std::cout << "Type 'fileguard' to open FileGuard menu.\n";
    std::cout << "Type 'ports' to manage firewall ports (open/close/block).\n";
    std::cout << "Type 'web install' to install the web interface.\n";
    std::cout << "Type 'web status | web url | web remove' to manage it.\n";
    std::cout << "Type 'exit' to disconnect and return to the server list.\n";
    std::cout << "\n";
    std::cout << "Type 'help' for detailed information.\n";
    std::cout << "\n";

    std::string currentDirectory = ".";

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

        if (!std::getline(std::cin >> std::ws, command))
        {
            std::cin.clear();
            break;
        }

        command = trim(command);

        if (command.empty())
        {
            continue;
        }

        if (command == "exit" || command == "servers")
        {
            break;
        }

        try
        {
            if (command == "help")
            {
                showHelp();

                continue;
            }

            {
                std::string lc = toLower(command);

                if (lc == "webinstall" || lc == "web-install")
                    lc = "web install";

                if (lc == "web" || lc.rfind("web ", 0) == 0)
                {
                    std::string arg = trim(lc.substr(3));

                    handleWebCommand(arg, webServer);

                    continue;
                }
            }

            if (command == "nano" || command.rfind("nano ", 0) == 0)
            {
                std::string arg = trim(command.substr(4));

                runNano(session, cfg.password, currentDirectory, arg);

                continue;
            }

            if (command == "ports" || command.rfind("ports ", 0) == 0)
            {
                if (firewall)
                    firewall->handle(trim(command.substr(5)));
                else
                    std::cout << "Port manager is not available.\n";

                continue;
            }

            if (command == "security")
            {
                if (security)
                    security->menu();
                else
                    std::cout << "Security module is not available.\n";

                continue;
            }

            if (command == "telegram")
            {
                if (telegramBot)
                    telegramBot->menu();
                else
                    std::cout << "Telegram Bot module is not available.\n";

                continue;
            }

            if (command == "hardening")
            {
                if (sshHardening)
                    sshHardening->menu();
                else
                    std::cout << "SSH Hardening module is not available.\n";

                continue;
            }

            if (
                command == "sshkeys" ||
                command == "ssh-key-guard" ||
                command == "sshkeyguard")
            {
                if (sshKeyGuard)
                    sshKeyGuard->menu();
                else
                    std::cout << "SSH Key Guard is not available.\n";

                continue;
            }

            if (command == "fileguard")
            {
                fileGuard.menu();

                continue;
            }

            if (command == "ls")
            {
                executeCommand(
                    session,
                    "cd \"" + currentDirectory + "\" && ls"
                );

                continue;
            }

            if (command == "pwd")
            {
                executeCommand(
                    session,
                    "cd \"" + currentDirectory + "\" && pwd"
                );

                continue;
            }

            if (command.rfind("cd ", 0) == 0)
            {
                std::string directory = trim(command.substr(3));

                if (directory.empty())
                {
                    continue;
                }

                changeDirectory(session, currentDirectory, directory);

                continue;
            }

            std::cout
                << "Unknown command: "
                << command
                << "\n";

            std::cout
                << "Available commands: "
                << "help, ls, pwd, cd, nano, security, telegram, "
                << "hardening, sshkeys, fileguard, ports, web, exit\n";
        }
        catch (const std::exception& e)
        {
            std::cout << "\nCommand failed: " << e.what() << "\n";
        }
        catch (...)
        {
            std::cout << "\nCommand failed (unknown error).\n";
        }
    }
}


// ============================================================
//  One connected session (modules + terminal + cleanup)
// ============================================================

static void runSession(Config& cfg, SOCKET& sock, LIBSSH2_SESSION*& session)
{
    {
        SSHKeyGuard sshKeyGuard(session, cfg.password);

        Security security(session, cfg.password);

        bool isKeyAuthentication = (cfg.auth == AuthMethod::PublicKey);

        SSHHardening sshHardening(
            session,
            cfg.password,
            isKeyAuthentication
        );

        TelegramBot telegramBot(session, cfg.password);

        FirewallManager firewall(
            session,
            cfg.password,
            cfg.username,
            cfg.port
        );

        WebServer webServer(
            webRootPath(),
            "127.0.0.1",
            8472,

            session,

            &sshKeyGuard,
            &security,
            &sshHardening,
            &telegramBot
        );

        if (!webServer.isRunning())
        {
            if (webServer.start())
            {
                std::cout
                    << "[WebServer] Web interface: "
                    << "http://127.0.0.1:8472\n";
            }
            else
            {
                std::cout
                    << "\nWeb interface is not installed. "
                    "Type 'web install' to install it.\n";
            }
        }

        try
        {
            runServerTerminal(
                session,
                cfg,
                &telegramBot,
                &sshKeyGuard,
                &security,
                &sshHardening,
                &webServer,
                &firewall
            );
        }
        catch (const std::exception& e)
        {
            std::cout << "\nSession error: " << e.what() << "\n";
        }
        catch (...)
        {
            std::cout << "\nSession error (unknown).\n";
        }

        std::cout << "\nStopping Web Server...\n";

        try { webServer.stop(); }
        catch (...) {}
    }

    std::cout << "Disconnecting...\n";

    closeConnection(session, sock, "Normal shutdown", true);

    std::cout << "Disconnected.\n";
}


// ============================================================
//  Connect to a profile (with retry / edit / back)
// ============================================================

enum class FailAction
{
    Retry,
    Edit,
    Back
};

static FailAction askFailAction(const Config& cfg)
{
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "        CONNECTION FAILED\n";
    std::cout << "========================================\n\n";

    std::cout << "Server: " << cfg.name << "\n";
    std::cout << "Method: " << authMethodTitle(cfg.auth) << "\n\n";

    switch (cfg.auth)
    {
    case AuthMethod::PublicKey:
        std::cout << "1. Retry (enter passphrase again)\n";
        break;

    case AuthMethod::Agent:
        std::cout << "1. Retry (check that the agent is running "
            "and has your key loaded)\n";
        break;

    default:
        std::cout << "1. Retry (enter password again)\n";
        break;
    }

    std::cout << "2. Edit this server (address / user / auth method)\n";
    std::cout << "3. Back to server list\n\n";

    while (true)
    {
        std::string input = readLine("Select: ");

        if (input == "1") return FailAction::Retry;
        if (input == "2") return FailAction::Edit;
        if (input == "3") return FailAction::Back;

        std::cout << "Invalid option. Please select 1, 2 or 3.\n";

        if (!std::cin.good())
        {
            std::cin.clear();
            return FailAction::Back;
        }
    }
}

// Ask for secrets that are not stored in the profile
static void ensureSecrets(Config& cfg)
{
    switch (cfg.auth)
    {
    case AuthMethod::Password:
    case AuthMethod::Interactive:

        if (cfg.password.empty())
            cfg.password = readSecret("Password for " + cfg.username + ": ");
        break;

    case AuthMethod::PublicKey:

        if (cfg.passphrase.empty())
            cfg.passphrase = readSecret("Key passphrase (Enter if none): ");

        if (cfg.password.empty())
            cfg.password = readSecret(
                "Sudo password for server modules (Enter to skip): ");
        break;

    case AuthMethod::Agent:

        if (cfg.password.empty())
            cfg.password = readSecret(
                "Sudo password for server modules (Enter to skip): ");
        break;
    }
}

static void connectToServer(std::vector<Config>& all, size_t index)
{
    while (true)
    {
        Config& cfg = all[index];

        std::cout
            << "\n========================================\n"
            << "        SERVER CONNECTION\n"
            << "========================================\n"
            << "Name:   " << cfg.name << "\n"
            << "Server: " << cfg.host << ":" << cfg.port << "\n"
            << "User:   " << cfg.username << "\n"
            << "Auth:   " << authMethodTitle(cfg.auth) << "\n";

        ensureSecrets(cfg);

        SOCKET sock = INVALID_SOCKET;
        LIBSSH2_SESSION* session = nullptr;

        bool opened = false;

        try
        {
            opened = openConnection(cfg, sock, session);
        }
        catch (...)
        {
            std::cout << "\nUnexpected error while connecting.\n";

            closeConnection(session, sock, "", false);

            opened = false;
        }

        if (opened)
        {
            runSession(cfg, sock, session);

            // do not keep secrets in memory after the session
            if (!cfg.savePassword)
                cfg.password.clear();

            cfg.passphrase.clear();

            return;
        }

        FailAction action = askFailAction(cfg);

        // forget wrong secrets so they are asked again
        cfg.passphrase.clear();

        if (!cfg.savePassword || action == FailAction::Retry)
            cfg.password.clear();

        if (action == FailAction::Back)
            return;

        if (action == FailAction::Edit)
        {
            if (editProfile(cfg, false))
            {
                if (!saveProfiles(all))
                    std::cout << "Warning: cannot save servers.cfg\n";
            }
        }
    }
}


// ============================================================
//  Server list (main menu)
// ============================================================

static void printServerList(const std::vector<Config>& list)
{
    std::cout << "\n";
    std::cout << "=========================================================\n";
    std::cout << "                  SERVERGUARD - MY SERVERS\n";
    std::cout << "=========================================================\n";

    if (list.empty())
    {
        std::cout << "\n  No servers yet. Type 'a' to add your first server.\n";
    }
    else
    {
        std::cout << "\n"
            << std::left
            << "  " << std::setw(4) << "#"
            << std::setw(20) << "Name"
            << std::setw(24) << "Address"
            << std::setw(14) << "User"
            << "Auth\n";

        std::cout << "  " << std::string(70, '-') << "\n";

        for (size_t i = 0; i < list.size(); i++)
        {
            const Config& c = list[i];

            std::string name = c.name.size() > 18
                ? c.name.substr(0, 17) + "~" : c.name;

            std::string user = c.username.size() > 12
                ? c.username.substr(0, 11) + "~" : c.username;

            std::cout
                << "  " << std::setw(4) << (i + 1)
                << std::setw(20) << name
                << std::setw(24) << (c.host + ":" + std::to_string(c.port))
                << std::setw(14) << user
                << authMethodTitle(c.auth) << "\n";
        }
    }

    std::cout << "\n  Type a server number (e.g. 1) to connect\n";
    std::cout << "  a = add   e 1 = edit server 1   d 1 = delete server 1   q = quit\n\n";
}

static bool parseIndex(const std::string& s, size_t count, size_t& out)
{
    try
    {
        size_t pos = 0;
        int n = std::stoi(s, &pos);

        if (pos != s.size() || n < 1 || static_cast<size_t>(n) > count)
            return false;

        out = static_cast<size_t>(n - 1);

        return true;
    }
    catch (...)
    {
        return false;
    }
}

static void serverMenu()
{
    while (true)
    {
        std::vector<Config> servers = loadProfiles();

        printServerList(servers);

        std::string input = trim(readLine("Select: "));

        if (!std::cin.good())
        {
            // input stream closed - leave quietly
            std::cin.clear();
            return;
        }

        if (input.empty())
            continue;

        std::string lc = toLower(input);

        if (lc == "q" || lc == "quit" || lc == "exit")
        {
            return;
        }

        if (lc == "a" || lc == "add")
        {
            Config c;

            if (editProfile(c, true))
            {
                servers.push_back(c);

                if (saveProfiles(servers))
                    std::cout << "\nServer \"" << c.name << "\" saved.\n";
                else
                    std::cout << "\nWarning: cannot save servers.cfg\n";
            }

            continue;
        }

        if (lc[0] == 'e' || lc[0] == 'd')
        {
            std::string arg = trim(lc.substr(1));

            if (lc.rfind("edit", 0) == 0)   arg = trim(lc.substr(4));
            if (lc.rfind("delete", 0) == 0) arg = trim(lc.substr(6));

            size_t idx = 0;

            if (!parseIndex(arg, servers.size(), idx))
            {
                std::cout << "Usage: " << lc[0] << " <server number>\n";
                continue;
            }

            if (lc[0] == 'e')
            {
                Config c = servers[idx];

                if (editProfile(c, false))
                {
                    servers[idx] = c;

                    if (saveProfiles(servers))
                        std::cout << "\nServer updated.\n";
                    else
                        std::cout << "\nWarning: cannot save servers.cfg\n";
                }
            }
            else
            {
                if (askYesNo("Delete \"" + servers[idx].name + "\"?", false))
                {
                    servers.erase(servers.begin() + idx);

                    if (saveProfiles(servers))
                        std::cout << "\nServer deleted.\n";
                    else
                        std::cout << "\nWarning: cannot save servers.cfg\n";
                }
            }

            continue;
        }

        std::string numArg = lc;

        {
            std::stringstream ts(lc);
            std::string a, b;

            ts >> a >> b;

            if (a == "c" || a == "connect")      numArg = b;
            else if (b == "c" || b == "connect") numArg = a;
        }

        size_t idx = 0;

        if (parseIndex(numArg, servers.size(), idx))
        {
            try
            {
                connectToServer(servers, idx);
            }
            catch (const std::exception& e)
            {
                std::cout << "\nError: " << e.what() << "\n";
            }
            catch (...)
            {
                std::cout << "\nUnknown error.\n";
            }

            continue;
        }

        std::cout << "Unknown command. Use a number, a, e <n>, d <n> or q.\n";
    }
}


// ============================================================
//  main
// ============================================================

int main()
{
    std::cout << "=============================\n";
    std::cout << "        ServerGuard\n";
    std::cout << "=============================\n";

    WSADATA wsadata;

    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
    {
        std::cout << "WSAStartup failed.\n";

        return 1;
    }

    if (libssh2_init(0) != 0)
    {
        std::cout << "libssh2 initialization failed.\n";

        WSACleanup();

        return 1;
    }

    try
    {
        migrateLegacyConfig();

        serverMenu();
    }
    catch (const std::exception& e)
    {
        std::cout << "\nFatal error: " << e.what() << "\n";
    }
    catch (...)
    {
        std::cout << "\nFatal error (unknown).\n";
    }

    std::cout << "\nServerGuard closed by user.\n";

    libssh2_exit();

    WSACleanup();

    return 0;
}