#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../WebServer.h"
#include "../SSHKeyGuard.h"
#include "WebServerHelpers.h"

#include <mutex>
#include <sstream>
#include <string>

void WebServer::handleSshKeyGuard(
    SOCKET clientSocket,
    const std::string& method,
    const std::string& action
)
{
    SSHKeyGuard* guard =
        sshKeyGuard.load();

    if (guard == nullptr)
    {
        sendJson(
            clientSocket,
            503,
            "{\"error\":\"SSH Key Guard is not connected\"}"
        );

        return;
    }

    std::lock_guard<std::mutex> lock(
        apiMutex
    );

    if (action == "status")
    {
        if (method != "GET")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        std::string status =
            guard->webStatus();

        sendJson(
            clientSocket,
            200,
            status
        );

        return;
    }

    if (action == "events")
    {
        if (method != "GET")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        std::string events =
            guard->webEvents();

        std::ostringstream json;

        json
            << "{"
            << "\"ok\":true,"
            << "\"text\":\""
            << jsonEscape(events)
            << "\""
            << "}";

        sendJson(
            clientSocket,
            200,
            json.str()
        );

        return;
    }

    if (action == "logs")
    {
        if (method != "GET")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        std::string logs =
            guard->webLogs();

        std::ostringstream json;

        json
            << "{"
            << "\"ok\":true,"
            << "\"text\":\""
            << jsonEscape(logs)
            << "\""
            << "}";

        sendJson(
            clientSocket,
            200,
            json.str()
        );

        return;
    }

    if (action == "install")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webInstall();

        std::string status =
            guard->webStatus();

        status =
            addOkToJson(
                status,
                result
            );

        sendJson(
            clientSocket,
            result ? 200 : 500,
            status
        );

        return;
    }

    if (action == "remove")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webRemove();

        std::string status =
            guard->webStatus();

        status =
            addOkToJson(
                status,
                result
            );

        sendJson(
            clientSocket,
            result ? 200 : 500,
            status
        );

        return;
    }

    if (action == "start")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webStart();

        std::string status =
            guard->webStatus();

        status =
            addOkToJson(
                status,
                result
            );

        sendJson(
            clientSocket,
            result ? 200 : 500,
            status
        );

        return;
    }

    if (action == "stop")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webStop();

        std::string status =
            guard->webStatus();

        status =
            addOkToJson(
                status,
                result
            );

        sendJson(
            clientSocket,
            result ? 200 : 500,
            status
        );

        return;
    }

    if (action == "restart")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webRestart();

        std::string status =
            guard->webStatus();

        status =
            addOkToJson(
                status,
                result
            );

        sendJson(
            clientSocket,
            result ? 200 : 500,
            status
        );

        return;
    }

    if (action == "baseline")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webBaseline();

        std::ostringstream json;

        json
            << "{"
            << "\"ok\":"
            << (result ? "true" : "false")
            << "}";

        sendJson(
            clientSocket,
            result ? 200 : 500,
            json.str()
        );

        return;
    }

    if (action == "scan")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webScan();

        std::ostringstream json;

        json
            << "{"
            << "\"ok\":"
            << (result ? "true" : "false")
            << "}";

        sendJson(
            clientSocket,
            result ? 200 : 500,
            json.str()
        );

        return;
    }

    if (action == "audit")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webAudit();

        std::ostringstream json;

        json
            << "{"
            << "\"ok\":"
            << (result ? "true" : "false")
            << "}";

        sendJson(
            clientSocket,
            result ? 200 : 500,
            json.str()
        );

        return;
    }

    if (action == "update")
    {
        if (method != "POST")
        {
            sendJson(
                clientSocket,
                405,
                "{\"error\":\"Method not allowed\"}"
            );

            return;
        }

        bool result =
            guard->webUpdate();

        std::string status =
            guard->webStatus();

        status =
            addOkToJson(
                status,
                result
            );

        sendJson(
            clientSocket,
            result ? 200 : 500,
            status
        );

        return;
    }

    sendJson(
        clientSocket,
        404,
        "{\"error\":\"SSH Key Guard endpoint not found\"}"
    );
}