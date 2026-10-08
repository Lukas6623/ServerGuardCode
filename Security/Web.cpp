#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "Web.h"
#include "WebServer.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;


// Манифест с адресом и SHA256 архива сайта
static const char* MANIFEST_URL =
"https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/updates/manifest.json";

static const size_t MAX_MANIFEST_BYTES = 256 * 1024;
static const size_t MAX_ZIP_BYTES = 64 * 1024 * 1024;


// ===================== ПУТИ =====================

std::string webBaseDir()
{
    char* value = nullptr;
    size_t len = 0;

    if (_dupenv_s(&value, &len, "LOCALAPPDATA") != 0 || !value)
    {
        return "";
    }

    std::string result = std::string(value) + "\\ServerGuard";

    free(value);

    return result;
}


std::string webRootPath()
{
    std::string base = webBaseDir();

    if (base.empty())
    {
        // запасной вариант, если LOCALAPPDATA недоступна
        return "C:\\Program Files\\ServerGuard\\web";
    }

    return base + "\\web";
}


static fs::path shaFilePath()
{
    return fs::path(webBaseDir()) / "web.sha256";
}


static std::string installedSha()
{
    std::ifstream in(shaFilePath());

    std::string value;

    std::getline(in, value);

    return value;
}


// ===================== ВСПОМОГАТЕЛЬНОЕ =====================

static std::string lowerCopy(std::string s)
{
    std::transform(
        s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
    );

    return s;
}


static std::string trimCopy(const std::string& s)
{
    size_t a = 0;
    size_t b = s.size();

    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;

    return s.substr(a, b - a);
}


// Достаёт строковое значение "key": "value" из простого JSON
static std::string jsonString(const std::string& json, const std::string& key)
{
    std::string needle = "\"" + key + "\"";

    size_t p = json.find(needle);

    if (p == std::string::npos)
        return "";

    p = json.find(':', p + needle.size());

    if (p == std::string::npos)
        return "";

    p = json.find('"', p + 1);

    if (p == std::string::npos)
        return "";

    size_t e = json.find('"', p + 1);

    if (e == std::string::npos)
        return "";

    std::string value = json.substr(p + 1, e - p - 1);

    // \/ -> /
    size_t pos = 0;

    while ((pos = value.find("\\/", pos)) != std::string::npos)
    {
        value.replace(pos, 2, "/");
        pos += 1;
    }

    return trimCopy(value);
}


struct WinHttpHandle
{
    HINTERNET h = nullptr;

    WinHttpHandle() = default;
    explicit WinHttpHandle(HINTERNET handle) : h(handle) {}

    ~WinHttpHandle()
    {
        if (h)
            WinHttpCloseHandle(h);
    }

    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;
};


// Скачивание по HTTPS (редиректы GitHub обрабатываются автоматически)
static bool httpGet(const std::string& url, std::string& out, size_t maxBytes)
{
    out.clear();

    std::wstring wurl(url.begin(), url.end());

    wchar_t host[256] = {};
    wchar_t path[2048] = {};
    wchar_t extra[2048] = {};

    URL_COMPONENTSW uc = {};
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2048;
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = 2048;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc))
    {
        std::cout << "Invalid URL: " << url << "\n";
        return false;
    }

    if (uc.nScheme != INTERNET_SCHEME_HTTPS)
    {
        std::cout << "Only https:// URLs are allowed: " << url << "\n";
        return false;
    }

    std::wstring objectName = std::wstring(path) + extra;

    WinHttpHandle session(
        WinHttpOpen(
            L"ServerGuard/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        )
    );

    if (!session.h)
    {
        std::cout << "WinHttpOpen failed (" << GetLastError() << ").\n";
        return false;
    }

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif

    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;

    WinHttpSetOption(
        session.h,
        WINHTTP_OPTION_SECURE_PROTOCOLS,
        &protocols,
        sizeof(protocols)
    );

    WinHttpSetTimeouts(session.h, 15000, 15000, 30000, 60000);

    WinHttpHandle connection(
        WinHttpConnect(session.h, host, uc.nPort, 0)
    );

    if (!connection.h)
    {
        std::cout << "Cannot connect to " << url << " (" << GetLastError() << ").\n";
        return false;
    }

    WinHttpHandle request(
        WinHttpOpenRequest(
            connection.h,
            L"GET",
            objectName.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        )
    );

    if (!request.h)
    {
        std::cout << "WinHttpOpenRequest failed (" << GetLastError() << ").\n";
        return false;
    }

    if (
        !WinHttpSendRequest(
            request.h,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0) ||
        !WinHttpReceiveResponse(request.h, nullptr))
    {
        std::cout << "Request failed (" << GetLastError() << ").\n";
        return false;
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);

    WinHttpQueryHeaders(
        request.h,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status,
        &statusSize,
        WINHTTP_NO_HEADER_INDEX
    );

    if (status != 200)
    {
        std::cout << "Server returned HTTP " << status << ".\n";
        return false;
    }

    while (true)
    {
        DWORD available = 0;

        if (!WinHttpQueryDataAvailable(request.h, &available))
        {
            std::cout << "Download error (" << GetLastError() << ").\n";
            return false;
        }

        if (available == 0)
            break;

        if (out.size() + available > maxBytes)
        {
            std::cout << "Download is too large.\n";
            return false;
        }

        size_t old = out.size();

        out.resize(old + available);

        DWORD read = 0;

        if (!WinHttpReadData(request.h, &out[old], available, &read))
        {
            std::cout << "Download error (" << GetLastError() << ").\n";
            return false;
        }

        out.resize(old + read);
    }

    return true;
}


static bool sha256Hex(const std::string& data, std::string& hex)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    if (!BCRYPT_SUCCESS(
        BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
    {
        return false;
    }

    DWORD objectLength = 0;
    DWORD copied = 0;

    bool ok =
        BCRYPT_SUCCESS(
            BCryptGetProperty(
                alg,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectLength),
                sizeof(objectLength),
                &copied,
                0));

    std::vector<UCHAR> object(ok ? objectLength : 0);

    UCHAR digest[32] = {};

    ok = ok &&
        BCRYPT_SUCCESS(
            BCryptCreateHash(
                alg, &hash,
                object.data(), objectLength,
                nullptr, 0, 0)) &&
        BCRYPT_SUCCESS(
            BCryptHashData(
                hash,
                reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                static_cast<ULONG>(data.size()),
                0)) &&
        BCRYPT_SUCCESS(
            BCryptFinishHash(hash, digest, sizeof(digest), 0));

    if (hash)
        BCryptDestroyHash(hash);

    BCryptCloseAlgorithmProvider(alg, 0);

    if (!ok)
        return false;

    static const char* digits = "0123456789abcdef";

    hex.clear();

    for (UCHAR b : digest)
    {
        hex += digits[b >> 4];
        hex += digits[b & 0x0F];
    }

    return true;
}


static DWORD runProcess(std::wstring commandLine)
{
    STARTUPINFOW si = {};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(
        nullptr,
        commandLine.data(),
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi))
    {
        return static_cast<DWORD>(-1);
    }

    WaitForSingleObject(pi.hProcess, 120000);

    DWORD exitCode = static_cast<DWORD>(-1);

    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return exitCode;
}


static std::wstring psQuote(const std::wstring& s)
{
    std::wstring r;

    for (wchar_t c : s)
    {
        if (c == L'\'')
            r += L"''";
        else
            r += c;
    }

    return r;
}


static bool extractZip(const fs::path& zip, const fs::path& dest)
{
    std::wstring cmd =
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
        L"\"Expand-Archive -LiteralPath '" + psQuote(zip.wstring()) +
        L"' -DestinationPath '" + psQuote(dest.wstring()) +
        L"' -Force\"";

    if (runProcess(cmd) == 0)
        return true;

    // запасной вариант: tar.exe есть в Windows 10+
    std::wstring tar =
        L"tar.exe -xf \"" + zip.wstring() +
        L"\" -C \"" + dest.wstring() + L"\"";

    return runProcess(tar) == 0;
}


// ===================== УСТАНОВКА =====================

bool installWebFiles()
{
    std::error_code ec;

    std::string base = webBaseDir();

    if (base.empty())
    {
        std::cout << "LOCALAPPDATA is not available.\n";
        return false;
    }

    fs::path baseDir(base);
    fs::path target(webRootPath());
    fs::path tmpDir = baseDir / "web_tmp";
    fs::path zipPath = baseDir / "web_download.zip";

    fs::create_directories(baseDir, ec);

    if (ec)
    {
        std::cout << "Cannot create folder: " << baseDir.string()
            << " (" << ec.message() << ")\n";
        return false;
    }

    auto cleanup = [&]()
        {
            std::error_code e;
            fs::remove_all(tmpDir, e);
            fs::remove(zipPath, e);
        };

    // 1. манифест
    std::cout << "Reading manifest...\n";

    std::string manifest;

    if (!httpGet(MANIFEST_URL, manifest, MAX_MANIFEST_BYTES))
    {
        std::cout << "Cannot download manifest.json.\n";
        return false;
    }

    std::string webUrl = jsonString(manifest, "web_url");
    std::string webSha = lowerCopy(jsonString(manifest, "web_sha256"));

    if (webUrl.empty() || webSha.size() != 64)
    {
        std::cout << "manifest.json has no valid web_url / web_sha256.\n";
        return false;
    }

    // 2. скачивание архива
    std::cout << "Downloading: " << webUrl << "\n";

    std::string zipData;

    if (!httpGet(webUrl, zipData, MAX_ZIP_BYTES))
    {
        std::cout << "Cannot download web archive.\n";
        return false;
    }

    std::cout << "Downloaded " << (zipData.size() / 1024) << " KB.\n";

    // 3. проверка SHA256
    std::string actualSha;

    if (!sha256Hex(zipData, actualSha))
    {
        std::cout << "Cannot calculate SHA256.\n";
        return false;
    }

    if (actualSha != webSha)
    {
        std::cout << "SHA256 mismatch! Installation aborted.\n";
        std::cout << "Expected: " << webSha << "\n";
        std::cout << "Actual:   " << actualSha << "\n";
        return false;
    }

    std::cout << "SHA256 verified.\n";

    // 4. сохраняем и распаковываем во временную папку
    {
        std::ofstream out(zipPath, std::ios::binary | std::ios::trunc);

        if (!out)
        {
            std::cout << "Cannot write " << zipPath.string() << "\n";
            return false;
        }

        out.write(zipData.data(), static_cast<std::streamsize>(zipData.size()));

        if (!out)
        {
            std::cout << "Cannot write " << zipPath.string() << "\n";
            cleanup();
            return false;
        }
    }

    fs::remove_all(tmpDir, ec);
    fs::create_directories(tmpDir, ec);

    std::cout << "Extracting...\n";

    if (!extractZip(zipPath, tmpDir))
    {
        std::cout << "Cannot extract archive.\n";
        cleanup();
        return false;
    }

    // 5. ищем папку с index.html (в корне или в единственной подпапке)
    fs::path sourceRoot;

    if (fs::exists(tmpDir / "index.html", ec))
    {
        sourceRoot = tmpDir;
    }
    else
    {
        for (const auto& entry : fs::directory_iterator(tmpDir, ec))
        {
            if (entry.is_directory(ec) &&
                fs::exists(entry.path() / "index.html", ec))
            {
                sourceRoot = entry.path();
                break;
            }
        }
    }

    if (sourceRoot.empty())
    {
        std::cout << "index.html not found in the archive.\n";
        cleanup();
        return false;
    }

    // 6. заменяем старую версию новой
    fs::remove_all(target, ec);

    fs::rename(sourceRoot, target, ec);

    if (ec)
    {
        std::cout << "Cannot install web files: " << ec.message() << "\n";
        cleanup();
        return false;
    }

    cleanup();

    {
        std::ofstream shaOut(shaFilePath(), std::ios::trunc);
        shaOut << webSha << '\n';
    }

    std::cout << "Web installed to: " << target.string() << "\n";

    return true;
}


bool removeWebFiles()
{
    std::error_code ec;

    fs::remove_all(webRootPath(), ec);

    if (ec)
    {
        std::cout << "Cannot remove web files: " << ec.message() << "\n";
        return false;
    }

    fs::remove(shaFilePath(), ec);

    return true;
}


// ===================== КОМАНДА web =====================

void handleWebCommand(const std::string& arg, WebServer* webServer)
{
    if (!webServer)
    {
        std::cout << "Web server is not available.\n";
        return;
    }

    if (arg == "install" || arg == "update")
    {
        if (!installWebFiles())
            return;

        if (!webServer->isRunning())
        {
            if (webServer->start())
            {
                std::cout << "Open: " << webServer->accessUrl() << "\n";
            }
            else
            {
                std::cout
                    << "Web files installed, "
                    "but the server failed to start.\n";
            }
        }
        else
        {
            std::cout
                << "Web server is running: "
                << webServer->accessUrl()
                << "\n";
        }

        return;
    }

    if (arg == "status")
    {
        std::error_code ec;

        bool installed =
            fs::exists(fs::path(webRootPath()) / "index.html", ec);

        std::string sha = installedSha();

        std::cout << "Web root:  " << webRootPath() << "\n";
        std::cout << "Installed: " << (installed ? "yes" : "no") << "\n";

        if (installed && !sha.empty())
            std::cout << "SHA256:    " << sha << "\n";

        std::cout << "Running:   "
            << (webServer->isRunning() ? "yes" : "no") << "\n";

        return;
    }

    if (arg == "url")
    {
        if (webServer->isRunning())
        {
            std::cout << webServer->accessUrl() << "\n";
        }
        else
        {
            std::cout
                << "Web server is not running. "
                "Type 'web install'.\n";
        }

        return;
    }

    if (arg == "remove")
    {
        webServer->stop();

        if (removeWebFiles())
            std::cout << "Web removed.\n";

        return;
    }

    std::cout
        << "Usage: web install | web update | web status | web url | web remove\n";
}