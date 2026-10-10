#pragma once

#include <string>

class WebServer;


std::string webBaseDir();


std::string webRootPath();


bool installWebFiles();


bool removeWebFiles();


void handleWebCommand(const std::string& arg, WebServer* webServer);