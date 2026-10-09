#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../WebServer.h"

#include <iostream>
#include <mutex>

void WebServer::stop()
{
    bool expected = true;

    if (
        !running.compare_exchange_strong(
            expected,
            false
        )
        )
    {
        return;
    }

    SOCKET socketToClose =
        serverSocket.exchange(
            INVALID_SOCKET
        );

    if (socketToClose != INVALID_SOCKET)
    {
        shutdown(
            socketToClose,
            SD_BOTH
        );

        closesocket(socketToClose);
    }

    if (serverThread.joinable())
    {
        serverThread.join();
    }

    {
        std::lock_guard<std::mutex> lock(
            clientsMutex
        );

        for (SOCKET client : clients)
        {
            shutdown(
                client,
                SD_BOTH
            );

            closesocket(client);
        }
    }

    {
        std::unique_lock<std::mutex> lock(
            clientsMutex
        );

        clientsCv.wait(
            lock,
            [this]()
            {
                return clients.empty();
            }
        );
    }

    WSACleanup();

    std::cout
        << "[WebServer] Stopped"
        << std::endl;
}