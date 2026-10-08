#pragma once

#include <string>

class WebServer;

// %LOCALAPPDATA%\ServerGuard
// (например C:\Users\<user>\AppData\Local\ServerGuard)
std::string webBaseDir();

// %LOCALAPPDATA%\ServerGuard\web  <- отсюда читается сайт
std::string webRootPath();

// Копирует сайт в webRootPath() (или создаёт страницу-заглушку)
bool installWebFiles();

// Удаляет установленный сайт
bool removeWebFiles();

// Обработка команды: web install | status | url | remove
void handleWebCommand(const std::string& arg, WebServer* webServer);