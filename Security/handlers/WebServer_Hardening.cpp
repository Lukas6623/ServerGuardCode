#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../WebServer.h"
#include "../SSHHardening.h"
#include "WebServerHelpers.h"

#include <mutex>
#include <string>

void WebServer::handleHardening(
    SOCKET clientSocket,
    const std::string& method,
    const std::string& action
)
{
    SSHHardening* module =
        hardening.load();

    if (module == nullptr)
    {
        sendJson(
            clientSocket,
            503,
            "{\"error\":\"SSH Hardening module is not connected\"}"
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
            module->webStatus();

        sendJson(
            clientSocket,
            200,
            status
        );

        return;
    }

    if (action == "backups")
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

        std::string backups =
            module->webBackups();

        sendJson(
            clientSocket,
            200,
            backups
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
            module->webInstall();

        std::string status =
            module->webStatus();

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

    if (action == "apply")
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
            module->webApply();

        std::string status =
            module->webStatus();

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

    if (action == "validate")
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
            module->webValidate();

        std::string status =
            module->webStatus();

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
            module->webUpdate();

        std::string status =
            module->webStatus();

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
            module->webRemove();

        std::string status =
            module->webStatus();

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
        "{\"error\":\"SSH Hardening endpoint not found\"}"
    );
}