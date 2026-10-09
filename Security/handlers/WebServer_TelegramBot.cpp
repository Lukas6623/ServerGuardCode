#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../WebServer.h"
#include "../TelegramBot.h"
#include "WebServerHelpers.h"

#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

void WebServer::handleTelegramBot(
    SOCKET clientSocket,
    const std::string& method,
    const std::string& action,
    const std::string& body
)
{
    TelegramBot* bot =
        telegramBot.load();

    if (bot == nullptr)
    {
        sendJson(
            clientSocket,
            503,
            "{\"error\":\"Telegram Bot is not connected\"}"
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
            bot->webStatus();

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
            bot->webLogs();

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

        std::string token;

        const std::string key =
            "\"token\"";

        std::size_t keyPos =
            body.find(key);

        if (keyPos != std::string::npos)
        {
            std::size_t colonPos =
                body.find(
                    ':',
                    keyPos + key.size()
                );

            if (colonPos != std::string::npos)
            {
                std::size_t start =
                    body.find(
                        '"',
                        colonPos + 1
                    );

                if (start != std::string::npos)
                {
                    ++start;

                    std::size_t end =
                        body.find(
                            '"',
                            start
                        );

                    if (end != std::string::npos)
                    {
                        token =
                            body.substr(
                                start,
                                end - start
                            );
                    }
                }
            }
        }

        if (token.empty())
        {
            sendJson(
                clientSocket,
                400,
                "{\"ok\":false,\"error\":\"Telegram Bot token is required\"}"
            );

            return;
        }

        std::cout
            << "\n[WEB TELEGRAM INSTALL]\n";

        std::cout
            << "Token received from web: YES\n";

        bool result =
            bot->webInstall(token);

        std::string status =
            bot->webStatus();

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
            bot->webStart();

        std::string status =
            bot->webStatus();

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
            bot->webStop();

        std::string status =
            bot->webStatus();

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
            bot->webRestart();

        std::string status =
            bot->webStatus();

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
            bot->webDisable();

        std::string status =
            bot->webStatus();

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
            bot->webUpdate();

        std::string status =
            bot->webStatus();

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

    if (action == "generate-code")
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
            bot->webGenerateCode();

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
            bot->webRemove();

        std::string status =
            bot->webStatus();

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
        "{\"error\":\"Telegram Bot endpoint not found\"}"
    );
}