#define NOMINMAX
#include <iomanip>
#include "WebServer.h"
#include <iomanip>
#include <sstream>
#include "SSHKeyGuard.h"
#include "Security.h"
#include "SSHHardening.h"
#include "TelegramBot.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <chrono>

static constexpr size_t MAX_HEADER_BYTES = 16 * 1024;
static constexpr size_t MAX_BODY_BYTES = 64 * 1024;
static constexpr size_t MAX_FILE_BYTES = 32 * 1024 * 1024;
static constexpr size_t MAX_CLIENTS = 32;

static constexpr int SOCKET_TIMEOUT_MS = 15000;

static const char* AUTH_COOKIE = "sg_token";

static std::string toLower(std::string value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(std::tolower(c));
        }
    );

    return value;
}

static std::string trim(const std::string& value)
{
    size_t start = 0;

    while (
        start < value.size() &&
        std::isspace(
            static_cast<unsigned char>(value[start])
        )
        )
    {
        ++start;
    }

    size_t end = value.size();

    while (
        end > start &&
        std::isspace(
            static_cast<unsigned char>(value[end - 1])
        )
        )
    {
        --end;
    }

    return value.substr(start, end - start);
}

static bool hasSuffix(
    const std::string& value,
    const std::string& suffix
)
{
    if (value.size() < suffix.size())
        return false;

    return value.compare(
        value.size() - suffix.size(),
        suffix.size(),
        suffix
    ) == 0;
}

static bool safeEquals(
    const std::string& a,
    const std::string& b
)
{
    if (a.size() != b.size())
        return false;

    unsigned char diff = 0;

    for (size_t i = 0; i < a.size(); ++i)
    {
        diff |= static_cast<unsigned char>(
            a[i] ^ b[i]
            );
    }

    return diff == 0;
}

static std::string generateToken()
{
    std::random_device rd;

    std::mt19937_64 generator(
        static_cast<unsigned long long>(rd()) ^
        static_cast<unsigned long long>(
            std::chrono::high_resolution_clock::
            now().
            time_since_epoch().
            count()
            )
    );

    std::ostringstream output;

    output
        << std::hex
        << std::setfill('0');

    for (int i = 0; i < 4; ++i)
    {
        output
            << std::setw(16)
            << generator();
    }

    return output.str();
}

static std::string queryParam(
    const std::string& query,
    const std::string& wanted
)
{
    size_t position = 0;

    while (position < query.size())
    {
        size_t ampersand =
            query.find('&', position);

        if (ampersand == std::string::npos)
        {
            ampersand = query.size();
        }

        std::string part =
            query.substr(
                position,
                ampersand - position
            );

        size_t equal =
            part.find('=');

        if (equal != std::string::npos)
        {
            std::string key =
                part.substr(
                    0,
                    equal
                );

            std::string value =
                part.substr(
                    equal + 1
                );

            if (key == wanted)
            {
                return value;
            }
        }

        position = ampersand + 1;
    }

    return "";
}

static std::string getHeader(
    const HttpRequest& request,
    const std::string& name
)
{
    std::string wanted =
        toLower(name);

    auto iterator =
        request.headers.find(wanted);

    if (iterator == request.headers.end())
    {
        return "";
    }

    return iterator->second;
}

static std::string statusText(int status)
{
    switch (status)
    {
    case 200:
        return "OK";

    case 201:
        return "Created";

    case 204:
        return "No Content";

    case 302:
        return "Found";

    case 400:
        return "Bad Request";

    case 401:
        return "Unauthorized";

    case 403:
        return "Forbidden";

    case 404:
        return "Not Found";

    case 405:
        return "Method Not Allowed";

    case 409:
        return "Conflict";

    case 413:
        return "Payload Too Large";

    case 500:
        return "Internal Server Error";

    case 503:
        return "Service Unavailable";

    default:
        return "Error";
    }
}

WebServer::WebServer(
    const std::string& webRoot,
    const std::string& host,
    int port,
    LIBSSH2_SESSION* session,
    SSHKeyGuard* sshKeyGuard,
    Security* security,
    SSHHardening* hardening,
    TelegramBot* telegramBot
)
    : webRoot(webRoot),
    host(host),
    port(port),
    session(session),
    sshKeyGuard(sshKeyGuard),
    security(security),
    hardening(hardening),
    telegramBot(telegramBot),
    serverSocket(INVALID_SOCKET),
    running(false)
{
    allowedHosts.push_back(
        toLower(host) +
        ":" +
        std::to_string(port)
    );

    allowedHosts.push_back(
        "localhost:" +
        std::to_string(port)
    );
}

WebServer::~WebServer()
{
    stop();
}

void WebServer::setSSHKeyGuard(
    SSHKeyGuard* guard
)
{
    sshKeyGuard.store(guard);
}

void WebServer::setSecurity(
    Security* securityModule
)
{
    security.store(securityModule);
}

void WebServer::setHardening(
    SSHHardening* hardeningModule
)
{
    hardening.store(hardeningModule);
}

void WebServer::setTelegramBot(
    TelegramBot* telegramModule
)
{
    telegramBot.store(telegramModule);
}

std::string WebServer::accessUrl() const
{
    return
        "http://" +
        host +
        ":" +
        std::to_string(port) +
        "/?token=" +
        token;
}

bool WebServer::start()
{
    if (running.load())
        return true;

    token = generateToken();

    try
    {
        std::filesystem::path root(webRoot);

        if (
            !std::filesystem::exists(root) ||
            !std::filesystem::is_directory(root)
            )
        {
            std::cerr
                << "[WebServer] Web root does not exist: "
                << webRoot
                << std::endl;

            return false;
        }

        std::filesystem::path index =
            root / "index.html";

        if (!std::filesystem::exists(index))
        {
            std::cerr
                << "[WebServer] index.html not found: "
                << index.string()
                << std::endl;

            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    WSADATA wsaData{};

    int wsaResult =
        WSAStartup(
            MAKEWORD(2, 2),
            &wsaData
        );

    if (wsaResult != 0)
    {
        std::cerr
            << "[WebServer] WSAStartup failed: "
            << wsaResult
            << std::endl;

        return false;
    }

    SOCKET listenSocket =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP
        );

    if (listenSocket == INVALID_SOCKET)
    {
        std::cerr
            << "[WebServer] socket() failed: "
            << WSAGetLastError()
            << std::endl;

        WSACleanup();

        return false;
    }

    BOOL exclusive = TRUE;

    setsockopt(
        listenSocket,
        SOL_SOCKET,
        SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&exclusive),
        sizeof(exclusive)
    );

    sockaddr_in address{};

    address.sin_family = AF_INET;

    address.sin_port =
        htons(
            static_cast<u_short>(port)
        );

    if (
        host == "0.0.0.0" ||
        host == "*" ||
        host.empty()
        )
    {
        address.sin_addr.s_addr =
            htonl(INADDR_ANY);
    }
    else
    {
        if (
            inet_pton(
                AF_INET,
                host.c_str(),
                &address.sin_addr
            ) != 1
            )
        {
            std::cerr
                << "[WebServer] Invalid host: "
                << host
                << std::endl;

            closesocket(listenSocket);
            WSACleanup();

            return false;
        }
    }

    if (
        bind(
            listenSocket,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        ) == SOCKET_ERROR
        )
    {
        std::cerr
            << "[WebServer] bind() failed: "
            << WSAGetLastError()
            << std::endl;

        closesocket(listenSocket);
        WSACleanup();

        return false;
    }

    if (
        listen(
            listenSocket,
            SOMAXCONN
        ) == SOCKET_ERROR
        )
    {
        std::cerr
            << "[WebServer] listen() failed: "
            << WSAGetLastError()
            << std::endl;

        closesocket(listenSocket);
        WSACleanup();

        return false;
    }

    serverSocket.store(listenSocket);
    running.store(true);

    serverThread =
        std::thread(
            &WebServer::serverLoop,
            this
        );

    std::cout
        << "[WebServer] Started: "
        << accessUrl()
        << std::endl;

    if (sshKeyGuard.load())
    {
        std::cout
            << "[WebServer] SSH Key Guard connected"
            << std::endl;
    }

    if (security.load())
    {
        std::cout
            << "[WebServer] Security connected"
            << std::endl;
    }

    if (hardening.load())
    {
        std::cout
            << "[WebServer] SSH Hardening connected"
            << std::endl;
    }

    if (telegramBot.load())
    {
        std::cout
            << "[WebServer] Telegram Bot connected"
            << std::endl;
    }

    return true;
}

bool WebServer::isRunning() const
{
    return running.load();
}

void WebServer::serverLoop()
{
    while (running.load())
    {
        SOCKET listenSocket =
            serverSocket.load();

        if (listenSocket == INVALID_SOCKET)
        {
            break;
        }

        sockaddr_in clientAddress{};

        int clientAddressSize =
            sizeof(clientAddress);

        SOCKET clientSocket =
            accept(
                listenSocket,
                reinterpret_cast<sockaddr*>(&clientAddress),
                &clientAddressSize
            );

        if (clientSocket == INVALID_SOCKET)
        {
            if (!running.load())
                break;

            continue;
        }

        bool accepted = false;

        {
            std::lock_guard<std::mutex> lock(
                clientsMutex
            );

            if (clients.size() < MAX_CLIENTS)
            {
                clients.insert(clientSocket);
                accepted = true;
            }
        }

        if (!accepted)
        {
            sendResponse(
                clientSocket,
                503,
                "text/plain; charset=utf-8",
                "Too many connections."
            );

            closesocket(clientSocket);
            continue;
        }

        int timeout = SOCKET_TIMEOUT_MS;

        setsockopt(
            clientSocket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeout),
            sizeof(timeout)
        );

        setsockopt(
            clientSocket,
            SOL_SOCKET,
            SO_SNDTIMEO,
            reinterpret_cast<const char*>(&timeout),
            sizeof(timeout)
        );

        std::thread(
            [this, clientSocket]()
            {
                handleClient(clientSocket);

                closesocket(clientSocket);

                {
                    std::lock_guard<std::mutex> lock(
                        clientsMutex
                    );

                    clients.erase(clientSocket);
                }

                clientsCv.notify_all();
            }
        ).detach();
    }
}

bool WebServer::readRequest(
    SOCKET clientSocket,
    HttpRequest& request,
    int& errorStatus
)
{
    errorStatus = 400;

    std::string buffer;

    buffer.reserve(4096);

    char temp[4096];

    while (true)
    {
        int received =
            recv(
                clientSocket,
                temp,
                sizeof(temp),
                0
            );

        if (received <= 0)
        {
            return false;
        }

        buffer.append(
            temp,
            received
        );

        if (
            buffer.size() >
            MAX_HEADER_BYTES +
            MAX_BODY_BYTES
            )
        {
            errorStatus = 413;
            return false;
        }

        size_t headerEnd =
            buffer.find("\r\n\r\n");

        if (
            headerEnd ==
            std::string::npos
            )
        {
            continue;
        }

        size_t headerSize =
            headerEnd + 4;

        if (headerSize > MAX_HEADER_BYTES)
        {
            errorStatus = 413;
            return false;
        }

        std::string headerPart =
            buffer.substr(
                0,
                headerEnd
            );

        std::istringstream stream(
            headerPart
        );

        std::string requestLine;

        if (
            !std::getline(
                stream,
                requestLine
            )
            )
        {
            return false;
        }

        if (
            !requestLine.empty() &&
            requestLine.back() == '\r'
            )
        {
            requestLine.pop_back();
        }

        std::istringstream requestStream(
            requestLine
        );

        std::string httpVersion;

        if (
            !(requestStream
                >> request.method
                >> request.target
                >> httpVersion)
            )
        {
            return false;
        }

        if (
            httpVersion != "HTTP/1.0" &&
            httpVersion != "HTTP/1.1"
            )
        {
            return false;
        }

        size_t question =
            request.target.find('?');

        if (question == std::string::npos)
        {
            request.path =
                request.target;

            request.query.clear();
        }
        else
        {
            request.path =
                request.target.substr(
                    0,
                    question
                );

            request.query =
                request.target.substr(
                    question + 1
                );
        }

        std::string line;

        while (
            std::getline(
                stream,
                line
            )
            )
        {
            if (
                !line.empty() &&
                line.back() == '\r'
                )
            {
                line.pop_back();
            }

            if (line.empty())
                continue;

            size_t colon =
                line.find(':');

            if (colon == std::string::npos)
            {
                continue;
            }

            std::string name =
                toLower(
                    trim(
                        line.substr(
                            0,
                            colon
                        )
                    )
                );

            std::string value =
                trim(
                    line.substr(
                        colon + 1
                    )
                );

            request.headers[name] = value;
        }

        size_t contentLength = 0;

        auto lengthIterator =
            request.headers.find(
                "content-length"
            );

        if (
            lengthIterator !=
            request.headers.end()
            )
        {
            try
            {
                unsigned long long parsed =
                    std::stoull(
                        lengthIterator->second
                    );

                if (parsed > MAX_BODY_BYTES)
                {
                    errorStatus = 413;
                    return false;
                }

                contentLength =
                    static_cast<size_t>(parsed);
            }
            catch (...)
            {
                return false;
            }
        }

        request.body.clear();

        size_t alreadyReceived =
            buffer.size() - headerSize;

        if (alreadyReceived > contentLength)
        {
            request.body =
                buffer.substr(
                    headerSize,
                    contentLength
                );

            return true;
        }

        if (alreadyReceived > 0)
        {
            request.body =
                buffer.substr(headerSize);
        }

        while (
            request.body.size() <
            contentLength
            )
        {
            int needed =
                static_cast<int>(
                    std::min(
                        sizeof(temp),
                        contentLength -
                        request.body.size()
                    )
                    );

            int received =
                recv(
                    clientSocket,
                    temp,
                    needed,
                    0
                );

            if (received <= 0)
            {
                return false;
            }

            request.body.append(
                temp,
                received
            );
        }

        return true;
    }
}

bool WebServer::isAuthorized(
    const HttpRequest& request
) const
{
    std::string cookie =
        getHeader(
            request,
            "cookie"
        );

    if (cookie.empty())
        return false;

    std::string wanted =
        std::string(AUTH_COOKIE) + "=";

    size_t position =
        cookie.find(wanted);

    while (position != std::string::npos)
    {
        if (
            position == 0 ||
            cookie[position - 1] == ';'
            )
        {
            size_t valueStart =
                position + wanted.size();

            size_t valueEnd =
                cookie.find(
                    ';',
                    valueStart
                );

            if (valueEnd == std::string::npos)
            {
                valueEnd = cookie.size();
            }

            std::string value =
                trim(
                    cookie.substr(
                        valueStart,
                        valueEnd - valueStart
                    )
                );

            return safeEquals(
                value,
                token
            );
        }

        position =
            cookie.find(
                wanted,
                position + 1
            );
    }

    return false;
}

void WebServer::handleClient(
    SOCKET clientSocket
)
{
    HttpRequest request;

    int errorStatus = 400;

    if (
        !readRequest(
            clientSocket,
            request,
            errorStatus
        )
        )
    {
        sendResponse(
            clientSocket,
            errorStatus,
            "text/plain; charset=utf-8",
            statusText(errorStatus)
        );

        return;
    }

    std::string requestHost =
        getHeader(
            request,
            "host"
        );

    if (!requestHost.empty())
    {
        requestHost =
            toLower(
                trim(requestHost)
            );

        bool hostAllowed = false;

        for (
            const std::string& allowed :
            allowedHosts
            )
        {
            if (requestHost == allowed)
            {
                hostAllowed = true;
                break;
            }
        }

        if (!hostAllowed)
        {
            sendResponse(
                clientSocket,
                403,
                "text/plain; charset=utf-8",
                "Invalid Host header."
            );

            return;
        }
    }

    std::string origin =
        getHeader(
            request,
            "origin"
        );

    if (!origin.empty())
    {
        std::string expected =
            "http://" +
            requestHost;

        if (origin != expected)
        {
            sendResponse(
                clientSocket,
                403,
                "text/plain; charset=utf-8",
                "Invalid Origin."
            );

            return;
        }
    }

    if (
        request.path == "/" &&
        !queryParam(
            request.query,
            "token"
        ).empty()
        )
    {
        std::string suppliedToken =
            queryParam(
                request.query,
                "token"
            );

        if (
            !safeEquals(
                suppliedToken,
                token
            )
            )
        {
            sendResponse(
                clientSocket,
                401,
                "text/plain; charset=utf-8",
                "Invalid token."
            );

            return;
        }

        std::string headers =
            "Set-Cookie: " +
            std::string(AUTH_COOKIE) +
            "=" +
            token +
            "; HttpOnly; SameSite=Strict; Path=/\r\n"
            "Location: /\r\n";

        sendResponse(
            clientSocket,
            302,
            "text/plain; charset=utf-8",
            "Redirecting...",
            headers
        );

        return;
    }

    if (!isAuthorized(request))
    {
        sendJson(
            clientSocket,
            401,
            "{\"error\":\"Unauthorized\"}"
        );

        return;
    }

    if (
        request.path.rfind(
            "/api/",
            0
        ) == 0
        )
    {
        handleApi(
            clientSocket,
            request
        );

        return;
    }

    serveStatic(
        clientSocket,
        request
    );
}

void WebServer::handleApi(
    SOCKET clientSocket,
    const HttpRequest& request
)
{
    const std::string& path =
        request.path;

    if (
        path.rfind(
            "/api/sshkeyguard/",
            0
        ) == 0
        )
    {
        std::string action =
            path.substr(
                std::string(
                    "/api/sshkeyguard/"
                ).size()
            );

        handleSshKeyGuard(
            clientSocket,
            request.method,
            action
        );

        return;
    }

    if (
        path.rfind(
            "/api/ssh-key-guard/",
            0
        ) == 0
        )
    {
        std::string action =
            path.substr(
                std::string(
                    "/api/ssh-key-guard/"
                ).size()
            );

        handleSshKeyGuard(
            clientSocket,
            request.method,
            action
        );

        return;
    }

    if (
        path.rfind(
            "/api/security/",
            0
        ) == 0
        )
    {
        std::string action =
            path.substr(
                std::string(
                    "/api/security/"
                ).size()
            );

        handleSecurity(
            clientSocket,
            request.method,
            action
        );

        return;
    }

    if (
        path == "/api/telegram" ||
        path.rfind(
            "/api/telegram/",
            0
        ) == 0
        )
    {
        std::string action;

        if (path == "/api/telegram")
        {
            action = "status";
        }
        else
        {
            action =
                path.substr(
                    std::string(
                        "/api/telegram/"
                    ).size()
                );
        }

        handleTelegramBot(
            clientSocket,
            request.method,
            action,
            request.body
        );

        return;
    }

    if (
        path == "/api/hardening" ||
        path.rfind(
            "/api/hardening/",
            0
        ) == 0
        )
    {
        std::string action;

        if (path == "/api/hardening")
        {
            action = "status";
        }
        else
        {
            action =
                path.substr(
                    std::string(
                        "/api/hardening/"
                    ).size()
                );
        }

        handleHardening(
            clientSocket,
            request.method,
            action
        );

        return;
    }

    if (
        request.method == "GET" &&
        path == "/api/health"
        )
    {
        bool sshKeys =
            sshKeyGuard.load() != nullptr;

        bool securityModule =
            security.load() != nullptr;

        bool hardeningModule =
            hardening.load() != nullptr;

        bool telegramModule =
            telegramBot.load() != nullptr;

        std::ostringstream json;

        json
            << "{"
            << "\"status\":\"ok\""
            << ",\"service\":\"ServerGuard\""
            << ",\"web_server\":true"
            << ",\"ssh_key_guard\":"
            << (sshKeys ? "true" : "false")
            << ",\"security\":"
            << (securityModule ? "true" : "false")
            << ",\"hardening\":"
            << (hardeningModule ? "true" : "false")
            << ",\"telegram\":"
            << (telegramModule ? "true" : "false")
            << "}";

        sendJson(
            clientSocket,
            200,
            json.str()
        );

        return;
    }

    if (
        request.method == "GET" &&
        path == "/api/server"
        )
    {
        sendJson(
            clientSocket,
            200,
            "{"
            "\"connected\":true,"
            "\"name\":\"ServerGuard\","
            "\"host\":\"connected\","
            "\"status\":\"online\""
            "}"
        );

        return;
    }

    if (
        request.method == "GET" &&
        path == "/api/server/stats"
        )
    {
        handleServerStats(clientSocket);

        return;
    }

    if (
        request.method == "GET" &&
        path == "/api/modules"
        )
    {
        bool sshKeys =
            sshKeyGuard.load() != nullptr;

        bool securityModule =
            security.load() != nullptr;

        bool hardeningModule =
            hardening.load() != nullptr;

        bool telegramModule =
            telegramBot.load() != nullptr;

        std::ostringstream json;

        json
            << "{"
            << "\"security\":"
            << (securityModule ? "true" : "false")
            << ",\"telegram\":"
            << (telegramModule ? "true" : "false")
            << ",\"hardening\":"
            << (hardeningModule ? "true" : "false")
            << ",\"sshkeys\":"
            << (sshKeys ? "true" : "false")
            << ",\"fileguard\":false"
            << "}";

        sendJson(
            clientSocket,
            200,
            json.str()
        );

        return;
    }

    if (
        request.method == "GET" &&
        path == "/api/dashboard"
        )
    {
        bool sshKeys =
            sshKeyGuard.load() != nullptr;

        Security* securityModule =
            security.load();

        bool hardeningModule =
            hardening.load() != nullptr;

        bool telegramModule =
            telegramBot.load() != nullptr;

        int servers = 0;

        if (
            sshKeys ||
            securityModule ||
            hardeningModule ||
            telegramModule
            )
        {
            servers = 1;
        }

        int links = 0;

        if (sshKeys)
            ++links;

        if (securityModule)
            ++links;

        if (hardeningModule)
            ++links;

        if (telegramModule)
            ++links;

        long long threats = 0;

        if (securityModule)
        {
            threats =
                securityModule->webThreats();
        }

        const char* status =
            servers > 0
            ? "online"
            : "offline";

        std::ostringstream json;

        json
            << "{"
            << "\"status\":\""
            << status
            << "\","
            << "\"servers\":"
            << servers
            << ","
            << "\"links\":"
            << links
            << ","
            << "\"threats\":"
            << threats
            << "}";

        sendJson(
            clientSocket,
            200,
            json.str()
        );

        return;
    }

    sendJson(
        clientSocket,
        404,
        "{\"error\":\"API endpoint not found\"}"
    );
}

void WebServer::serveStatic(
    SOCKET clientSocket,
    const HttpRequest& request
)
{
    if (
        request.method != "GET" &&
        request.method != "HEAD"
        )
    {
        sendResponse(
            clientSocket,
            405,
            "text/plain; charset=utf-8",
            "Method Not Allowed"
        );

        return;
    }

    std::string decoded =
        urlDecode(request.path);

    if (
        decoded.empty() ||
        decoded == "/"
        )
    {
        decoded = "/index.html";
    }

    if (
        decoded.find("..") != std::string::npos ||
        decoded.find('\\') != std::string::npos ||
        decoded.find(':') != std::string::npos ||
        decoded.find('\0') != std::string::npos
        )
    {
        sendResponse(
            clientSocket,
            403,
            "text/plain; charset=utf-8",
            "Forbidden"
        );

        return;
    }

    try
    {
        std::filesystem::path root =
            std::filesystem::weakly_canonical(
                std::filesystem::path(webRoot)
            );

        std::string relative =
            decoded;

        while (
            !relative.empty() &&
            (
                relative.front() == '/' ||
                relative.front() == '\\'
                )
            )
        {
            relative.erase(
                relative.begin()
            );
        }

        std::filesystem::path file =
            std::filesystem::weakly_canonical(
                root / relative
            );

        std::filesystem::path rootWithSlash =
            root;

        rootWithSlash +=
            std::filesystem::path::preferred_separator;

        std::string rootString =
            rootWithSlash.string();

        std::string fileString =
            file.string();

        if (
            fileString != root.string() &&
            fileString.rfind(
                rootString,
                0
            ) != 0
            )
        {
            sendResponse(
                clientSocket,
                403,
                "text/plain; charset=utf-8",
                "Forbidden"
            );

            return;
        }

        if (
            !std::filesystem::exists(file) ||
            !std::filesystem::is_regular_file(file)
            )
        {
            sendResponse(
                clientSocket,
                404,
                "text/plain; charset=utf-8",
                "Not Found"
            );

            return;
        }

        uintmax_t fileSize =
            std::filesystem::file_size(file);

        if (fileSize > MAX_FILE_BYTES)
        {
            sendResponse(
                clientSocket,
                413,
                "text/plain; charset=utf-8",
                "File Too Large"
            );

            return;
        }

        std::ifstream input(
            file,
            std::ios::binary
        );

        if (!input)
        {
            sendResponse(
                clientSocket,
                500,
                "text/plain; charset=utf-8",
                "Failed to open file."
            );

            return;
        }

        std::string content;

        content.resize(
            static_cast<size_t>(fileSize)
        );

        if (fileSize > 0)
        {
            input.read(
                content.data(),
                static_cast<std::streamsize>(fileSize)
            );

            if (!input)
            {
                sendResponse(
                    clientSocket,
                    500,
                    "text/plain; charset=utf-8",
                    "Failed to read file."
                );

                return;
            }
        }

        sendResponse(
            clientSocket,
            200,
            getContentType(file.string()),
            request.method == "HEAD"
            ? ""
            : content
        );
    }
    catch (...)
    {
        sendResponse(
            clientSocket,
            500,
            "text/plain; charset=utf-8",
            "Internal Server Error"
        );
    }
}

void WebServer::sendResponse(
    SOCKET clientSocket,
    int status,
    const std::string& contentType,
    const std::string& body,
    const std::string& extraHeaders
)
{
    std::ostringstream response;

    response
        << "HTTP/1.1 "
        << status
        << " "
        << statusText(status)
        << "\r\n";

    response
        << "Content-Type: "
        << contentType
        << "\r\n";

    response
        << "Content-Length: "
        << body.size()
        << "\r\n";

    response
        << "Cache-Control: no-store\r\n";

    response
        << "X-Content-Type-Options: nosniff\r\n";

    response
        << "X-Frame-Options: DENY\r\n";

    response
        << "Referrer-Policy: no-referrer\r\n";

    response
        << "Content-Security-Policy: "
        << "default-src 'self'; "
        << "script-src 'self' 'unsafe-inline'; "
        << "style-src 'self' 'unsafe-inline'; "
        << "frame-ancestors 'none'"
        << "\r\n";

    if (!extraHeaders.empty())
    {
        response
            << extraHeaders;
    }

    response
        << "Connection: close\r\n";

    response
        << "\r\n";

    response
        << body;

    std::string data =
        response.str();

    size_t sentTotal = 0;

    while (
        sentTotal <
        data.size()
        )
    {
        int sent =
            send(
                clientSocket,
                data.data() + sentTotal,
                static_cast<int>(
                    data.size() - sentTotal
                    ),
                0
            );

        if (sent <= 0)
            break;

        sentTotal +=
            static_cast<size_t>(sent);
    }
}

void WebServer::sendJson(
    SOCKET clientSocket,
    int status,
    const std::string& json
)
{
    sendResponse(
        clientSocket,
        status,
        "application/json; charset=utf-8",
        json
    );
}

std::string WebServer::getContentType(
    const std::string& path
)
{
    std::string lower =
        toLower(path);

    if (
        hasSuffix(lower, ".html") ||
        hasSuffix(lower, ".htm")
        )
    {
        return "text/html; charset=utf-8";
    }

    if (
        hasSuffix(lower, ".css")
        )
    {
        return "text/css; charset=utf-8";
    }

    if (
        hasSuffix(lower, ".js")
        )
    {
        return "application/javascript; charset=utf-8";
    }

    if (
        hasSuffix(lower, ".json")
        )
    {
        return "application/json; charset=utf-8";
    }

    if (
        hasSuffix(lower, ".svg")
        )
    {
        return "image/svg+xml";
    }

    if (
        hasSuffix(lower, ".png")
        )
    {
        return "image/png";
    }

    if (
        hasSuffix(lower, ".jpg") ||
        hasSuffix(lower, ".jpeg")
        )
    {
        return "image/jpeg";
    }

    if (
        hasSuffix(lower, ".gif")
        )
    {
        return "image/gif";
    }

    if (
        hasSuffix(lower, ".webp")
        )
    {
        return "image/webp";
    }

    if (
        hasSuffix(lower, ".ico")
        )
    {
        return "image/x-icon";
    }

    if (
        hasSuffix(lower, ".txt")
        )
    {
        return "text/plain; charset=utf-8";
    }

    if (
        hasSuffix(lower, ".woff")
        )
    {
        return "font/woff";
    }

    if (
        hasSuffix(lower, ".woff2")
        )
    {
        return "font/woff2";
    }

    return "application/octet-stream";
}

std::string WebServer::urlDecode(
    const std::string& value
)
{
    std::string result;

    result.reserve(value.size());

    auto hexValue =
        [](char c) -> int
        {
            if (
                c >= '0' &&
                c <= '9'
                )
            {
                return c - '0';
            }

            if (
                c >= 'a' &&
                c <= 'f'
                )
            {
                return c - 'a' + 10;
            }

            if (
                c >= 'A' &&
                c <= 'F'
                )
            {
                return c - 'A' + 10;
            }

            return -1;
        };

    for (
        size_t i = 0;
        i < value.size();
        ++i
        )
    {
        char c =
            value[i];

        if (
            c == '%' &&
            i + 2 < value.size()
            )
        {
            int high =
                hexValue(
                    value[i + 1]
                );

            int low =
                hexValue(
                    value[i + 2]
                );

            if (
                high >= 0 &&
                low >= 0
                )
            {
                result +=
                    static_cast<char>(
                        (high << 4) | low
                        );

                i += 2;

                continue;
            }
        }

        if (c == '+')
        {
            result += ' ';
        }
        else
        {
            result += c;
        }
    }

    return result;
}

std::string WebServer::jsonEscape(
    const std::string& value
)
{
    std::ostringstream output;

    for (
        unsigned char c :
    value
        )
    {
        switch (c)
        {
        case '\"':
            output << "\\\"";
            break;

        case '\\':
            output << "\\\\";
            break;

        case '\b':
            output << "\\b";
            break;

        case '\f':
            output << "\\f";
            break;

        case '\n':
            output << "\\n";
            break;

        case '\r':
            output << "\\r";
            break;

        case '\t':
            output << "\\t";
            break;

        default:

            if (c < 0x20)
            {
                output
                    << "\\u"
                    << std::hex
                    << std::setw(4)
                    << std::setfill('0')
                    << static_cast<int>(c)
                    << std::dec;
            }
            else
            {
                output
                    << static_cast<char>(c);
            }

            break;
        }
    }

    return output.str();
}

bool WebServer::executeSshCommand(
    const std::string& command,
    std::string& output
)
{
    output.clear();

    if (!session)
        return false;

    std::lock_guard<std::mutex> lock(apiMutex);

    LIBSSH2_CHANNEL* channel =
        libssh2_channel_open_session(session);

    if (!channel)
    {
        return false;
    }

    if (
        libssh2_channel_exec(
            channel,
            command.c_str()
        ) != 0
        )
    {
        libssh2_channel_free(channel);

        return false;
    }

    char buffer[8192];

    while (true)
    {
        int rc =
            libssh2_channel_read(
                channel,
                buffer,
                sizeof(buffer) - 1
            );

        if (rc > 0)
        {
            buffer[rc] = '\0';

            output.append(
                buffer,
                static_cast<size_t>(rc)
            );

            continue;
        }

        if (rc == 0)
        {
            break;
        }

        libssh2_channel_free(channel);

        return false;
    }

    libssh2_channel_send_eof(channel);

    libssh2_channel_wait_eof(channel);

    libssh2_channel_wait_closed(channel);

    int exitCode =
        libssh2_channel_get_exit_status(
            channel
        );

    libssh2_channel_free(channel);

    return exitCode == 0;
}