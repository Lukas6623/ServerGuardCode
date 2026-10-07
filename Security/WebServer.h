
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


// ============================================================
// FORWARD DECLARATIONS
// ============================================================

class SSHKeyGuard;
class Security;
class SSHHardening;


// ============================================================
// HTTP REQUEST
// ============================================================

struct HttpRequest
{
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::string body;

    std::map<std::string, std::string> headers;
};


// ============================================================
// WEB SERVER
// ============================================================
//
// ServerGuard Web Dashboard
//
// Responsible for:
//
//   - HTTP server
//   - Static website
//   - Authentication
//   - REST API
//   - SSH Key Guard API
//   - Security API
//   - SSH Hardening API
//   - Telegram Bot API
//   - Linux server statistics
//
// ============================================================

class WebServer
{
public:

    // ========================================================
    // CONSTRUCTOR
    // ========================================================

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


    // ========================================================
    // DESTRUCTOR
    // ========================================================

    ~WebServer();


    // ========================================================
    // COPY CONTROL
    // ========================================================

    WebServer(const WebServer&) = delete;

    WebServer& operator=(const WebServer&) = delete;


    // ========================================================
    // MODULE SETTERS
    // ========================================================

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


    // ========================================================
    // SERVER
    // ========================================================

    bool start();

    void stop();

    bool isRunning() const;

    std::string accessUrl() const;


private:

    // ========================================================
    // SERVER LOOP
    // ========================================================

    void serverLoop();


    // ========================================================
    // CLIENT
    // ========================================================

    void handleClient(
        SOCKET clientSocket
    );


    // ========================================================
    // HTTP REQUEST
    // ========================================================

    bool readRequest(
        SOCKET clientSocket,
        HttpRequest& request,
        int& errorStatus
    );


    // ========================================================
    // AUTHENTICATION
    // ========================================================

    bool isAuthorized(
        const HttpRequest& request
    ) const;


    // ========================================================
    // API
    // ========================================================

    void handleApi(
        SOCKET clientSocket,
        const HttpRequest& request
    );


    // ========================================================
    // SSH KEY GUARD API
    // ========================================================

    void handleSshKeyGuard(
        SOCKET clientSocket,
        const std::string& method,
        const std::string& action
    );


    // ========================================================
    // SECURITY API
    // ========================================================

    void handleSecurity(
        SOCKET clientSocket,
        const std::string& method,
        const std::string& action
    );


    // ========================================================
    // SSH HARDENING API
    // ========================================================

    void handleHardening(
        SOCKET clientSocket,
        const std::string& method,
        const std::string& action
    );


    // ========================================================
    // TELEGRAM BOT API
    // ========================================================

    void handleTelegramBot(
        SOCKET clientSocket,
        const std::string& method,
        const std::string& action,
        const std::string& body
    );


    // ========================================================
    // SERVER STATISTICS
    // ========================================================

    bool executeSshCommand(
        const std::string& command,
        std::string& output
    );


    void handleServerStats(
        SOCKET clientSocket
    );


    // ========================================================
    // STATIC FILES
    // ========================================================

    void serveStatic(
        SOCKET clientSocket,
        const HttpRequest& request
    );


    // ========================================================
    // HTTP RESPONSE
    // ========================================================

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


    // ========================================================
    // HELPERS
    // ========================================================

    static std::string getContentType(
        const std::string& path
    );


    static std::string urlDecode(
        const std::string& value
    );


    static std::string jsonEscape(
        const std::string& value
    );


    // ========================================================
    // CONFIGURATION
    // ========================================================

    std::string webRoot;

    std::string host;

    int port;


    // ========================================================
    // SERVERGUARD MODULES
    // ========================================================

    LIBSSH2_SESSION* session;

    std::atomic<SSHKeyGuard*> sshKeyGuard;

    std::atomic<Security*> security;

    std::atomic<SSHHardening*> hardening;

    std::atomic<TelegramBot*> telegramBot;


    // ========================================================
    // SERVER STATE
    // ========================================================

    std::atomic<SOCKET> serverSocket;

    std::atomic<bool> running;

    std::thread serverThread;


    // ========================================================
    // AUTHENTICATION
    // ========================================================

    std::string token;

    std::vector<std::string> allowedHosts;


    // ========================================================
    // API LOCK
    // ========================================================
    //
    // SSH/libssh2 operations are serialized because the
    // underlying SSH session must not be accessed from
    // multiple API requests simultaneously.
    //
    // TelegramBot uses the same SSH session, therefore
    // Telegram API requests are also protected by this mutex.
    //
    // ========================================================

    std::mutex apiMutex;


    // ========================================================
    // SERVER MONITORING
    // ========================================================

    // CPU monitoring
    unsigned long long previousCpuTotal = 0;

    unsigned long long previousCpuIdle = 0;


    // Network monitoring
    unsigned long long previousNetworkRx = 0;

    unsigned long long previousNetworkTx = 0;

    long long previousNetworkTimeMs = 0;


    // ========================================================
    // CLIENT MANAGEMENT
    // ========================================================

    std::mutex clientsMutex;

    std::condition_variable clientsCv;

    std::set<SOCKET> clients;
};
