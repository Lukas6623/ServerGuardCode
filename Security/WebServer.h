#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <libssh2.h>

#include "TelegramBot.h"

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

class SSHKeyGuard;
class Security;
class SSHHardening;

struct HttpRequest
{
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::string body;

    std::map<std::string, std::string> headers;
};

class WebServer
{
public:

    WebServer(
        const std::string& webRoot,
        const std::string& host,
        int port,

        LIBSSH2_SESSION* session,

        SSHKeyGuard* sshKeyGuard,

        Security* security = nullptr,

        SSHHardening* hardening = nullptr,

        TelegramBot* telegramBot = nullptr
    );

    ~WebServer();

    WebServer(const WebServer&) = delete;

    WebServer& operator=(const WebServer&) = delete;

    void setSSHKeyGuard(
        SSHKeyGuard* guard
    );

    void setSecurity(
        Security* securityModule
    );

    void setHardening(
        SSHHardening* hardeningModule
    );

    void setTelegramBot(
        TelegramBot* telegramModule
    );

    bool start();

    void stop();

    bool isRunning() const;

    std::string accessUrl() const;

private:

    void serverLoop();

    void handleClient(
        SOCKET clientSocket
    );

    bool readRequest(
        SOCKET clientSocket,
        HttpRequest& request,
        int& errorStatus
    );

    bool isAuthorized(
        const HttpRequest& request
    ) const;

    void handleApi(
        SOCKET clientSocket,
        const HttpRequest& request
    );

    void handleSshKeyGuard(
        SOCKET clientSocket,
        const std::string& method,
        const std::string& action
    );

    void handleSecurity(
        SOCKET clientSocket,
        const std::string& method,
        const std::string& action
    );

    void handleHardening(
        SOCKET clientSocket,
        const std::string& method,
        const std::string& action
    );

    void handleTelegramBot(
        SOCKET clientSocket,
        const std::string& method,
        const std::string& action,
        const std::string& body
    );

    bool executeSshCommand(
        const std::string& command,
        std::string& output
    );

    void handleServerStats(
        SOCKET clientSocket
    );

    void serveStatic(
        SOCKET clientSocket,
        const HttpRequest& request
    );

    void sendResponse(
        SOCKET clientSocket,
        int status,
        const std::string& contentType,
        const std::string& body,
        const std::string& extraHeaders = ""
    );

    void sendJson(
        SOCKET clientSocket,
        int status,
        const std::string& json
    );

    static std::string getContentType(
        const std::string& path
    );

    static std::string urlDecode(
        const std::string& value
    );

    static std::string jsonEscape(
        const std::string& value
    );

    std::string webRoot;

    std::string host;

    int port;

    LIBSSH2_SESSION* session;

    std::atomic<SSHKeyGuard*> sshKeyGuard;

    std::atomic<Security*> security;

    std::atomic<SSHHardening*> hardening;

    std::atomic<TelegramBot*> telegramBot;

    std::atomic<SOCKET> serverSocket;

    std::atomic<bool> running;

    std::thread serverThread;

    std::string token;

    std::vector<std::string> allowedHosts;

    std::mutex apiMutex;

    unsigned long long previousCpuTotal = 0;

    unsigned long long previousCpuIdle = 0;

    unsigned long long previousNetworkRx = 0;

    unsigned long long previousNetworkTx = 0;

    long long previousNetworkTimeMs = 0;

    std::mutex clientsMutex;

    std::condition_variable clientsCv;

    std::set<SOCKET> clients;
};