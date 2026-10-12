#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <winsock2.h>
#include <windows.h>
#include <libssh2.h>

class FirewallManager
{
public:
    FirewallManager(
        LIBSSH2_SESSION* session,
        const std::string& password,
        const std::string& username,
        int sshPort)
        : session_(session), password_(password),
        user_(username), sshPort_(sshPort)
    {}


    void handle(const std::string& arg)
    {
        if (arg.empty())
        {
            menu();
            return;
        }

        if (arg == "install")
        {
            install();
            return;
        }

        std::istringstream iss(arg);
        std::vector<std::string> tokens;
        std::string t;

        while (iss >> t)
            tokens.push_back(t);

        call(tokens);
    }

    void menu()
    {
        while (true)
        {
            std::cout << "\n========================================\n";
            std::cout << "          PORT MANAGER (UFW)\n";
            std::cout << "========================================\n";
            std::cout << " 1. Install / update on server (always-on service)\n";
            std::cout << " 2. Service status\n";
            std::cout << " 3. Firewall status\n";
            std::cout << " 4. Show rules (numbered)\n";
            std::cout << " 5. Listening ports\n";
            std::cout << " 6. Open port\n";
            std::cout << " 7. Close port (remove allow rule)\n";
            std::cout << " 8. Block port (deny)\n";
            std::cout << " 9. Unblock port (remove deny rule)\n";
            std::cout << "10. Limit port (anti-bruteforce)\n";
            std::cout << "11. Delete rule by number\n";
            std::cout << "12. Enable firewall\n";
            std::cout << "13. Disable firewall\n";
            std::cout << "14. Protected ports (list/add/remove)\n";
            std::cout << "15. Default policy (incoming/outgoing)\n";
            std::cout << "16. Remove service from server\n";
            std::cout << " 0. Back\n\n";

            std::string c = ask("Select: ");

            if (c == "0" || !std::cin.good()) return;
            else if (c == "1")  install();
            else if (c == "2")  call({ "service-status" });
            else if (c == "3")  call({ "status" });
            else if (c == "4")  call({ "rules" });
            else if (c == "5")  call({ "listening" });
            else if (c == "6")  portAction("allow", false);
            else if (c == "7")  portAction("close", true);
            else if (c == "8")  portAction("deny", true);
            else if (c == "9")  portAction("unblock", false);
            else if (c == "10") portAction("limit", false);
            else if (c == "11")
            {
                std::string n = ask("Rule number: ");
                if (!n.empty()) call({ "delete", n });
            }
            else if (c == "12") call({ "enable" });
            else if (c == "13")
            {
                if (confirm("Disable the firewall completely?"))
                    call({ "disable", "--force" });
            }
            else if (c == "14") protectedMenu();
            else if (c == "15")
            {
                std::string d = ask("Direction (incoming/outgoing): ");
                std::string p = ask("Policy (allow/deny/reject): ");
                if (!d.empty() && !p.empty())
                    call({ "default", d, p });
            }
            else if (c == "16")
            {
                if (confirm("Remove the service from the server?"))
                {
                    call({ "uninstall-service" });
                    installed_ = false;
                }
            }
            else std::cout << "Invalid option.\n";
        }
    }

private:
    LIBSSH2_SESSION* session_;
    std::string password_;
    std::string user_;
    int sshPort_;
    bool installed_ = false;

    static constexpr const char* kRemotePath =
        "/opt/serverguard/firewall_manager.py";

    static constexpr const char* kGithubRaw =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/firewall_manager.py";



    static std::string ask(const std::string& prompt)
    {
        std::cout << prompt;
        std::string s;
        std::getline(std::cin, s);

        size_t a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) return "";
        size_t b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    }

    static bool confirm(const std::string& q)
    {
        std::string a = ask(q + " (yes/no): ");
        return a == "yes" || a == "y";
    }

    void portAction(const std::string& action, bool offerForce)
    {
        std::string port = ask(
            "Port (80, 80/tcp, 8000:8100/tcp; no protocol = tcp+udp): ");

        if (port.empty()) return;

        std::string source = ask("Only from IP/CIDR (Enter = anywhere): ");

        std::vector<std::string> args = { action, port };

        if (!source.empty())
        {
            args.push_back("--from");
            args.push_back(source);
        }

        if (!ensureInstalled())
            return;

        std::string out;
        int rc = run(commandLine(args), out);
        std::cout << out;

        if (!out.empty() && out.back() != '\n')
            std::cout << "\n";

        if (rc == 3 && offerForce &&
            confirm("This port is protected. Force anyway?"))
        {
            args.push_back("--force");
            call(args);
        }
    }

    void protectedMenu()
    {
        call({ "protect", "list" });

        std::string a = ask("add / remove / Enter = back: ");

        if (a != "add" && a != "remove") return;

        std::string p = ask("Port (e.g. 22/tcp): ");

        if (!p.empty())
            call({ "protect", a, p });
    }



    static std::string q(const std::string& s)
    {
        std::string r = "'";

        for (char c : s)
        {
            if (c == '\'') r += "'\\''";
            else r += c;
        }

        return r + "'";
    }

    std::string commandLine(const std::vector<std::string>& args)
    {
        std::string cmd = std::string("python3 ") + kRemotePath;

        for (const auto& a : args)
            cmd += " " + q(a);

        return cmd;
    }


    int run(const std::string& command, std::string& out, bool useSudo = true)
    {
        out.clear();

        if (!session_)
        {
            out = "SSH session is not available.\n";
            return -1;
        }

        bool needSudo = useSudo && user_ != "root";
        bool feedPassword = needSudo && !password_.empty();

        std::string full = command;

        if (needSudo)
            full = (feedPassword ? "sudo -S -p '' " : "sudo -n ") + command;

        full += " 2>&1";

        LIBSSH2_CHANNEL* ch = libssh2_channel_open_session(session_);

        if (!ch)
        {
            out = "Cannot open SSH channel.\n";
            return -1;
        }

        if (libssh2_channel_exec(ch, full.c_str()) != 0)
        {
            out = "Cannot execute command.\n";
            libssh2_channel_free(ch);
            return -1;
        }

        if (feedPassword)
        {
            std::string pw = password_ + "\n";
            libssh2_channel_write(ch, pw.c_str(), pw.size());
        }

        libssh2_channel_send_eof(ch);

        char buf[4096];

        while (true)
        {
            auto rc = libssh2_channel_read(ch, buf, sizeof(buf));

            if (rc > 0) out.append(buf, static_cast<size_t>(rc));
            else break;
        }

        libssh2_channel_close(ch);
        libssh2_channel_wait_closed(ch);

        int status = libssh2_channel_get_exit_status(ch);

        libssh2_channel_free(ch);

        return status;
    }

    int call(const std::vector<std::string>& args)
    {
        if (!ensureInstalled())
            return -1;

        std::string out;
        int rc = run(commandLine(args), out);

        std::cout << out;

        if (!out.empty() && out.back() != '\n')
            std::cout << "\n";

        return rc;
    }

    bool ensureInstalled()
    {
        if (installed_) return true;

        std::string out;

        if (run(std::string("test -f ") + kRemotePath, out, false) == 0)
        {
            installed_ = true;
            return true;
        }

        std::cout << "Port manager is not installed on the server.\n";

        if (!confirm("Install it now?"))
            return false;

        return install();
    }



    static std::string readLocalScript()
    {
        std::vector<std::string> candidates = { "firewall_manager.py" };

        char path[MAX_PATH] = {};

        if (GetModuleFileNameA(nullptr, path, MAX_PATH))
        {
            std::string dir = path;
            size_t pos = dir.find_last_of("\\/");

            if (pos != std::string::npos)
                candidates.push_back(dir.substr(0, pos + 1) +
                    "firewall_manager.py");
        }

        for (const auto& c : candidates)
        {
            std::ifstream f(c, std::ios::binary);

            if (f.good())
            {
                std::stringstream ss;
                ss << f.rdbuf();
                return ss.str();
            }
        }

        return "";
    }

    static std::string base64(const std::string& in)
    {
        static const char* t =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string out;
        size_t i = 0;

        while (i + 2 < in.size())
        {
            unsigned v = (static_cast<unsigned char>(in[i]) << 16) |
                (static_cast<unsigned char>(in[i + 1]) << 8) |
                static_cast<unsigned char>(in[i + 2]);

            out += t[(v >> 18) & 63];
            out += t[(v >> 12) & 63];
            out += t[(v >> 6) & 63];
            out += t[v & 63];
            i += 3;
        }

        if (i + 1 == in.size())
        {
            unsigned v = static_cast<unsigned char>(in[i]) << 16;
            out += t[(v >> 18) & 63];
            out += t[(v >> 12) & 63];
            out += "==";
        }
        else if (i + 2 == in.size())
        {
            unsigned v = (static_cast<unsigned char>(in[i]) << 16) |
                (static_cast<unsigned char>(in[i + 1]) << 8);
            out += t[(v >> 18) & 63];
            out += t[(v >> 12) & 63];
            out += t[(v >> 6) & 63];
            out += '=';
        }

        return out;
    }


    bool downloadFromGithub(const std::string& dst)
    {
        std::string out;
        std::string url = kGithubRaw;

        std::string cmd =
            "rm -f " + dst + "; "
            "( command -v curl >/dev/null 2>&1 && "
            "curl -fsSL --max-time 30 '" + url + "' -o " + dst + " ) || "
            "( command -v wget >/dev/null 2>&1 && "
            "wget -q -T 30 -O " + dst + " '" + url + "' )";

        if (run(cmd, out, false) != 0)
        {
            std::cout << "Download from GitHub failed. " << out << "\n";
            return false;
        }

        if (run("grep -q 'ServerGuard Firewall Manager' " + dst, out, false) != 0)
        {
            std::cout << "Downloaded file is not firewall_manager.py.\n";
            return false;
        }

        return true;
    }


    bool uploadLocal(const std::string& tmpPy)
    {
        std::string script = readLocalScript();

        if (script.empty())
        {
            std::cout << "Local firewall_manager.py not found either.\n";
            return false;
        }

        std::string b64 = base64(script);
        std::string out;
        std::string tmpB64 = "/tmp/.sg_fw.b64";

        if (run("umask 077; : > " + tmpB64, out, false) != 0)
            return false;

        const size_t chunk = 6000;

        for (size_t pos = 0; pos < b64.size(); pos += chunk)
        {
            if (run("printf %s '" + b64.substr(pos, chunk) + "' >> " + tmpB64,
                out, false) != 0)
                return false;
        }

        bool ok = run("base64 -d " + tmpB64 + " > " + tmpPy, out, false) == 0;

        run("rm -f " + tmpB64, out, false);

        return ok;
    }

    bool install()
    {
        std::string out;
        const std::string tmpPy = "/tmp/.sg_fw.py";

        if (run("command -v python3", out, false) != 0)
        {
            std::cout << "python3 is not installed on the server.\n"
                "Run: sudo apt update && sudo apt install -y python3\n";
            return false;
        }

        std::cout << "Downloading firewall_manager.py from GitHub...\n";

        if (!downloadFromGithub(tmpPy))
        {
            std::cout << "Trying local file instead...\n";

            if (!uploadLocal(tmpPy))
            {
                std::cout << "Installation failed: no script source.\n";
                return false;
            }
        }

        std::cout << "Installing service...\n";

        int rc = run(
            "python3 " + tmpPy +
            " install-service --protect " + std::to_string(sshPort_),
            out);

        std::cout << out;

        if (!out.empty() && out.back() != '\n')
            std::cout << "\n";

        run("rm -f " + tmpPy, out, false);

        if (rc != 0)
        {
            std::cout << "Installation failed (exit code " << rc << ").\n";
            return false;
        }

        installed_ = true;

        std::cout << "SSH port " << sshPort_
            << " is now protected. Type 'ports' to manage.\n";

        return true;
    }
};