#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../WebServer.h"
#include "../Security.h"
#include "WebServerHelpers.h"

#include <mutex>
#include <sstream>
#include <string>

void WebServer::handleSecurity(
    SOCKET clientSocket,
    const std::string& method,
    const std::string& action
)
{
    Security* sec =
        security.load();

    if (sec == nullptr)
    {
        sendJson(
            clientSocket,
            503,
            "{\"error\":\"Security module is not connected\"}"
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
            sec->webStatus();

        sendJson(
            clientSocket,
            200,
            status
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
            sec->webLogs();

        std::ostringstream json;

        json
            << "{"
            << "\"ok\":true,"
            << "\"logs\":\""
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
            sec->webInstall();

        std::string status =
            sec->webStatus();

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
            sec->webStart();

        std::string status =
            sec->webStatus();

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
            sec->webStop();

        std::string status =
            sec->webStatus();

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

    if (action == "disable")
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
            sec->webDisable();

        std::string status =
            sec->webStatus();

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
            sec->webUpdate();

        std::string status =
            sec->webStatus();

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
        "{\"error\":\"Security endpoint not found\"}"
    );
}