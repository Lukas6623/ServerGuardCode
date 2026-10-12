#include "Help.h"

#include <iostream>

void showHelp()
{
    std::cout
        << "\n"
        << "============================================================\n"
        << "                     SERVERGUARD HELP\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "GENERAL COMMANDS\n"
        << "------------------------------------------------------------\n"
        << "\n";

    std::cout
        << "help\n"
        << "  Show this help page.\n"
        << "  Displays information about ServerGuard commands,\n"
        << "  modules and available management functions.\n"
        << "\n";

    std::cout
        << "ls\n"
        << "  List files and directories in the current remote\n"
        << "  directory on the Linux server.\n"
        << "\n";

    std::cout
        << "pwd\n"
        << "  Show the current remote directory.\n"
        << "\n";

    std::cout
        << "cd <directory>\n"
        << "  Change the current remote directory.\n"
        << "\n"
        << "  Examples:\n"
        << "    cd /opt\n"
        << "    cd /var/log\n"
        << "    cd ..\n"
        << "    cd /\n"
        << "\n";

    std::cout
        << "exit\n"
        << "  Close the SSH connection and exit ServerGuard.\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                     SECURITY MODULE\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "Command:\n"
        << "  security\n"
        << "\n";

    std::cout
        << "Purpose:\n"
        << "  ServerGuard SSH brute-force protection module.\n"
        << "\n";

    std::cout
        << "The module manages:\n"
        << "  - SSH brute-force protection\n"
        << "  - UFW firewall\n"
        << "  - SSH connection protection\n"
        << "  - systemd security service\n"
        << "  - brute-force detection script\n"
        << "\n";

    std::cout
        << "Security menu:\n"
        << "\n"
        << "  1. Install / enable protection\n"
        << "     Install and configure the protection module.\n"
        << "\n"
        << "  2. Start protection\n"
        << "     Start the ServerGuard security service.\n"
        << "\n"
        << "  3. Stop protection\n"
        << "     Stop the ServerGuard security service.\n"
        << "\n"
        << "  4. Disable automatic startup\n"
        << "     Disable automatic service startup.\n"
        << "\n"
        << "  5. Check status\n"
        << "     Check whether the protection service is running.\n"
        << "\n"
        << "  6. Show logs\n"
        << "     Display security service logs.\n"
        << "\n"
        << "  7. Update brute-force protection\n"
        << "     Download and install the newest protection script.\n"
        << "\n"
        << "  0. Back\n"
        << "     Return to the ServerGuard terminal.\n"
        << "\n";

    std::cout
        << "Security files:\n"
        << "  Script:\n"
        << "    /opt/serverguard/brute_force_guard.py\n"
        << "\n"
        << "  Data:\n"
        << "    /opt/serverguard/data\n"
        << "\n"
        << "  Service:\n"
        << "    serverguard-security.service\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                      FILE GUARD\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "Command:\n"
        << "  fileguard\n"
        << "\n";

    std::cout
        << "Purpose:\n"
        << "  FileGuard monitors protected files and detects\n"
        << "  unauthorized changes on the Linux server.\n"
        << "\n";

    std::cout
        << "FileGuard menu:\n"
        << "\n"
        << "  1. Install / enable FileGuard\n"
        << "     Install FileGuard and enable its service.\n"
        << "\n"
        << "  2. Start FileGuard\n"
        << "     Start the FileGuard service.\n"
        << "\n"
        << "  3. Stop FileGuard\n"
        << "     Stop the FileGuard service.\n"
        << "\n"
        << "  4. Disable automatic startup\n"
        << "     Prevent FileGuard from starting automatically.\n"
        << "\n"
        << "  5. Check status\n"
        << "     Check the current FileGuard service status.\n"
        << "\n"
        << "  6. Show logs\n"
        << "     Display FileGuard service logs.\n"
        << "\n"
        << "  7. Rebuild baseline\n"
        << "     Create a new baseline of protected files.\n"
        << "\n"
        << "  8. Update FileGuard\n"
        << "     Download, verify, backup and install a new\n"
        << "     FileGuard version.\n"
        << "\n"
        << "  0. Back\n"
        << "     Return to the ServerGuard terminal.\n"
        << "\n";

    std::cout
        << "FileGuard files:\n"
        << "  Script:\n"
        << "    /opt/serverguard/file_guard.py\n"
        << "\n"
        << "  Data:\n"
        << "    /opt/serverguard/data\n"
        << "\n"
        << "  Service:\n"
        << "    serverguard-fileguard.service\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                    SSH HARDENING\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "Command:\n"
        << "  hardening\n"
        << "\n";

    std::cout
        << "Purpose:\n"
        << "  SSH Hardening protects and validates the SSH\n"
        << "  configuration of the Linux server.\n"
        << "\n";

    std::cout
        << "SSH Hardening menu:\n"
        << "\n"
        << "  1. Apply SSH hardening\n"
        << "     Apply ServerGuard SSH security settings.\n"
        << "\n"
        << "  2. Check current SSH configuration\n"
        << "     Display the current SSH configuration.\n"
        << "\n"
        << "  3. Validate SSH configuration\n"
        << "     Check whether the SSH configuration is valid.\n"
        << "\n"
        << "  4. Show configuration backups\n"
        << "     Display available SSH configuration backups.\n"
        << "\n"
        << "  5. Restore configuration\n"
        << "     Restore a previous SSH configuration backup.\n"
        << "\n"
        << "  6. Update SSH Hardening\n"
        << "     Download and install a new SSH Hardening script.\n"
        << "\n"
        << "  0. Back\n"
        << "     Return to the ServerGuard terminal.\n"
        << "\n";

    std::cout
        << "SSH Hardening files:\n"
        << "  Script:\n"
        << "    /opt/serverguard/ssh_hardening.py\n"
        << "\n"
        << "  Backup:\n"
        << "    /opt/serverguard/backups/ssh-hardening/\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                     TELEGRAM BOT\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "Command:\n"
        << "  telegram\n"
        << "\n";

    std::cout
        << "Purpose:\n"
        << "  Manage the ServerGuard Telegram integration.\n"
        << "\n";

    std::cout
        << "The Telegram module is designed for:\n"
        << "  - ServerGuard notifications\n"
        << "  - Security event notifications\n"
        << "  - FileGuard event notifications\n"
        << "  - Server monitoring\n"
        << "  - Owner verification\n"
        << "  - Telegram bot management\n"
        << "\n";

    std::cout
        << "Telegram files:\n"
        << "  Directory:\n"
        << "    /opt/serverguard/telegram\n"
        << "\n";

    // ------------------------------------------------------------
    // PORT MANAGER
    // ------------------------------------------------------------

    std::cout
        << "============================================================\n"
        << "                      PORT MANAGER\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "Command:\n"
        << "  ports\n"
        << "\n";

    std::cout
        << "Purpose:\n"
        << "  Manage the server firewall (UFW) from the ServerGuard\n"
        << "  terminal: open, close, block and limit ports, manage\n"
        << "  rules and turn the firewall on or off.\n"
        << "\n"
        << "  A small always-on service on the server keeps your\n"
        << "  protected ports (SSH by default) allowed, so you do\n"
        << "  not lock yourself out.\n"
        << "\n";

    std::cout
        << "Requirements (on the server):\n"
        << "  - Ubuntu or Debian with UFW (apt install ufw)\n"
        << "  - python3, curl or wget, systemd\n"
        << "  - root, or a user with sudo (the sudo password given\n"
        << "    at login is used)\n"
        << "  - outgoing access to raw.githubusercontent.com\n"
        << "\n";

    std::cout
        << "First-time setup:\n"
        << "  1. Type:  ports\n"
        << "  2. Choose 1 (Install / update)\n"
        << "     (or type: ports install)\n"
        << "  3. Wait for: SSH port ... is now protected\n"
        << "  4. Check with menu item 2 (Service status)\n"
        << "\n"
        << "  The script is downloaded from GitHub by the server.\n"
        << "  If GitHub is unreachable, a local firewall_manager.py\n"
        << "  placed next to the program is uploaded instead.\n"
        << "  Running install again updates the service.\n"
        << "\n";

    std::cout
        << "Two ways to use it:\n"
        << "  Menu:     ports\n"
        << "            then choose a number, 0 = back\n"
        << "\n"
        << "  Direct:   ports <command> [arguments]\n"
        << "            Example: ports allow 8080/tcp\n"
        << "\n"
        << "  Commands are lowercase. Help for the script itself:\n"
        << "    ports -h\n"
        << "    ports allow -h\n"
        << "\n";

    std::cout
        << "Port format:\n"
        << "  80             port 80, both tcp and udp\n"
        << "  80/tcp         tcp only\n"
        << "  53/udp         udp only\n"
        << "  8000:8100/tcp  range (protocol is required)\n"
        << "\n"
        << "  Close a port with the same notation you used to open\n"
        << "  it: a rule created as 80 is removed with close 80.\n"
        << "\n";

    std::cout
        << "Port Manager menu:\n"
        << "\n"
        << "  1. Install / update on server\n"
        << "     Download the script and install the always-on\n"
        << "     service.\n"
        << "\n"
        << "  2. Service status\n"
        << "     Service state, autostart, firewall state, version.\n"
        << "\n"
        << "  3. Firewall status\n"
        << "     Full UFW status. Warns if UFW is disabled.\n"
        << "\n"
        << "  4. Show rules (numbered)\n"
        << "     List rules with numbers (used by item 11).\n"
        << "\n"
        << "  5. Listening ports\n"
        << "     Show which ports the server really listens on.\n"
        << "\n"
        << "  6. Open port\n"
        << "     Allow incoming traffic to a port.\n"
        << "\n"
        << "  7. Close port\n"
        << "     Remove the allow rule for a port.\n"
        << "\n"
        << "  8. Block port (deny)\n"
        << "     Silently drop traffic to a port.\n"
        << "\n"
        << "  9. Unblock port\n"
        << "     Remove the deny rule for a port.\n"
        << "\n"
        << "  10. Limit port (anti-bruteforce)\n"
        << "      Allow a port, but temporarily block IPs that\n"
        << "      connect too often.\n"
        << "\n"
        << "  11. Delete rule by number\n"
        << "      Remove a rule using its number from item 4.\n"
        << "\n"
        << "  12. Enable firewall\n"
        << "      Turn UFW on (protected ports are allowed first).\n"
        << "\n"
        << "  13. Disable firewall\n"
        << "      Turn UFW off (asks for confirmation).\n"
        << "\n"
        << "  14. Protected ports\n"
        << "      List, add or remove protected ports.\n"
        << "\n"
        << "  15. Default policy\n"
        << "      Set the default for incoming or outgoing traffic\n"
        << "      (allow / deny / reject).\n"
        << "\n"
        << "  16. Remove service from server\n"
        << "      Remove the service and script. UFW rules stay.\n"
        << "\n"
        << "  0. Back\n"
        << "     Return to the ServerGuard terminal.\n"
        << "\n"
        << "  Items 6-10 ask for a port and an optional IP or subnet\n"
        << "  (press Enter for 'from anywhere').\n"
        << "\n";

    std::cout
        << "Direct commands:\n"
        << "\n"
        << "  ports allow <port>        open a port\n"
        << "  ports deny <port>         block (drop)\n"
        << "  ports reject <port>       block (send refusal)\n"
        << "  ports limit <port>        open with rate limiting\n"
        << "  ports close <port>        remove allow rule\n"
        << "  ports unblock <port>      remove deny rule\n"
        << "  ports delete <number>     remove rule by number\n"
        << "  ports rules               numbered rule list\n"
        << "  ports status              UFW status\n"
        << "  ports listening           listening sockets\n"
        << "  ports enable              turn firewall on\n"
        << "  ports disable --force     turn firewall off\n"
        << "  ports default <dir> <pol> default policy\n"
        << "  ports logging <level>     on, off, low, medium,\n"
        << "                            high, full\n"
        << "  ports reload              reload rules\n"
        << "  ports protect list        show protected ports\n"
        << "  ports protect add <port>  protect a port\n"
        << "  ports protect remove <p>  remove protection\n"
        << "  ports service-status      service and firewall state\n"
        << "  ports install             install / update service\n"
        << "  ports uninstall-service   remove the service\n"
        << "  ports version             script version\n"
        << "\n"
        << "  Options for allow, deny, reject, limit, close, unblock:\n"
        << "    --from <IP or subnet>   apply the rule to one source\n"
        << "    --force                 allow changing a protected\n"
        << "                            port\n"
        << "\n"
        << "  Examples:\n"
        << "    ports allow 443/tcp\n"
        << "    ports allow 5432/tcp --from 203.0.113.10\n"
        << "    ports allow 8000:8100/tcp\n"
        << "    ports deny 3306\n"
        << "    ports limit 22/tcp\n"
        << "    ports default incoming deny\n"
        << "\n";

    std::cout
        << "Protected ports:\n"
        << "  Protected ports must always stay open. By default the\n"
        << "  SSH port you connected through is protected.\n"
        << "\n"
        << "  - Every 30 seconds the service checks them and restores\n"
        << "    missing allow rules (while UFW is enabled).\n"
        << "  - close, deny, reject and delete are refused for a\n"
        << "    protected port unless --force is used.\n"
        << "  - To really close a protected port, first remove its\n"
        << "    protection:  ports protect remove 22/tcp\n"
        << "    otherwise the service will restore the rule.\n"
        << "  - If SSH runs on another port, protect it:\n"
        << "    ports protect add 2222/tcp\n"
        << "  - Deleting a protected rule by number needs --force:\n"
        << "    ports delete 3 --force\n"
        << "\n";

    std::cout
        << "How to enable the firewall safely:\n"
        << "  1. ports listening        see what is running\n"
        << "  2. ports allow 80/tcp     open everything you need\n"
        << "     ports allow 443/tcp\n"
        << "  3. ports enable           the SSH port is allowed\n"
        << "                            automatically first\n"
        << "  4. ports default incoming deny\n"
        << "  5. ports status, ports rules   verify\n"
        << "  6. Open a SECOND connection and make sure it works\n"
        << "     before closing the current session.\n"
        << "\n"
        << "  While UFW is disabled, rules do NOT filter traffic.\n"
        << "  They take effect only after 'ports enable'.\n"
        << "\n";

    std::cout
        << "Common tasks:\n"
        << "  Open a web port:         ports allow 443/tcp\n"
        << "  Open a port for one IP:  ports allow 5432/tcp\n"
        << "                           --from 203.0.113.10\n"
        << "  Close a port:            ports close 443/tcp\n"
        << "  Block a port:            ports deny 3306\n"
        << "  Protect SSH from brute\n"
        << "  force:                   ports limit 22/tcp\n"
        << "  Delete rule number 3:    ports rules\n"
        << "                           ports delete 3\n"
        << "  (rule numbers shift after a deletion: list the rules\n"
        << "   again before deleting the next one)\n"
        << "\n";

    std::cout
        << "Important notes:\n"
        << "  - Opening a port does not start a service. If nothing\n"
        << "    listens on the port, connections still fail.\n"
        << "    Check with: ports listening\n"
        << "  - Ports published by Docker (-p 8080:80) bypass UFW,\n"
        << "    so these rules do not apply to them.\n"
        << "  - If IPv6 is enabled in UFW, rules apply to it too.\n"
        << "  - Disabling the firewall or removing the service does\n"
        << "    not delete existing UFW rules.\n"
        << "\n";

    std::cout
        << "Troubleshooting:\n"
        << "  python3 is not installed\n"
        << "    sudo apt update && sudo apt install -y python3\n"
        << "\n"
        << "  Download from GitHub failed\n"
        << "    Check internet, curl/wget and access to GitHub, or\n"
        << "    put firewall_manager.py next to the program.\n"
        << "\n"
        << "  sudo: a password is required\n"
        << "    The sudo password was not set at login. Enter it\n"
        << "    in the connection setup or enable passwordless sudo.\n"
        << "\n"
        << "  UFW is not installed\n"
        << "    sudo apt install ufw\n"
        << "\n"
        << "  REFUSED: port ... is protected\n"
        << "    See 'Protected ports' above (--force or\n"
        << "    ports protect remove).\n"
        << "\n"
        << "  Rule #N not found\n"
        << "    Run 'ports rules' and use the current number.\n"
        << "\n"
        << "  Strange characters instead of text\n"
        << "    The server has an old script version. Update it:\n"
        << "    ports -> 1 (Install / update).\n"
        << "\n"
        << "  Lost SSH access\n"
        << "    Log in through your hosting console (VNC/serial)\n"
        << "    and run: sudo ufw disable\n"
        << "\n";

    std::cout
        << "Port Manager files:\n"
        << "  Script:\n"
        << "    /opt/serverguard/firewall_manager.py\n"
        << "\n"
        << "  Protected ports list:\n"
        << "    /etc/serverguard/protected_ports\n"
        << "\n"
        << "  Service:\n"
        << "    serverguard-firewall.service\n"
        << "\n"
        << "  Service logs (on the server):\n"
        << "    journalctl -u serverguard-firewall -n 50\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                    SERVERGUARD MODULES\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "Security\n"
        << "  Protects SSH from brute-force attacks and manages\n"
        << "  the UFW firewall and security systemd service.\n"
        << "\n";

    std::cout
        << "FileGuard\n"
        << "  Monitors protected files and detects unauthorized\n"
        << "  modifications.\n"
        << "\n";

    std::cout
        << "SSH Hardening\n"
        << "  Hardens SSH configuration and provides validation,\n"
        << "  backup and restore functionality.\n"
        << "\n";

    std::cout
        << "Telegram Bot\n"
        << "  Provides remote notifications and ServerGuard\n"
        << "  event integration through Telegram.\n"
        << "\n";

    std::cout
        << "Port Manager\n"
        << "  Opens, closes, blocks and limits ports through UFW\n"
        << "  and keeps protected ports (SSH) always allowed.\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                     IMPORTANT PATHS\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "/opt/serverguard/\n"
        << "  Main ServerGuard directory.\n"
        << "\n";

    std::cout
        << "/opt/serverguard/data/\n"
        << "  Runtime data used by ServerGuard modules.\n"
        << "\n";

    std::cout
        << "/opt/serverguard/backups/\n"
        << "  Backups created before module updates.\n"
        << "\n";

    std::cout
        << "/opt/serverguard/telegram/\n"
        << "  Telegram Bot files and runtime data.\n"
        << "\n";

    std::cout
        << "/opt/serverguard/brute_force_guard.py\n"
        << "  SSH brute-force protection script.\n"
        << "\n";

    std::cout
        << "/opt/serverguard/file_guard.py\n"
        << "  FileGuard monitoring script.\n"
        << "\n";

    std::cout
        << "/opt/serverguard/ssh_hardening.py\n"
        << "  SSH Hardening script.\n"
        << "\n";

    std::cout
        << "/opt/serverguard/firewall_manager.py\n"
        << "  Port Manager script.\n"
        << "\n";

    std::cout
        << "/etc/serverguard/protected_ports\n"
        << "  List of ports the Port Manager keeps allowed.\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                    SYSTEMD SERVICES\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "serverguard-security.service\n"
        << "  SSH brute-force protection service.\n"
        << "\n";

    std::cout
        << "serverguard-fileguard.service\n"
        << "  FileGuard monitoring service.\n"
        << "\n";

    std::cout
        << "serverguard-firewall.service\n"
        << "  Port Manager service. Keeps protected ports allowed.\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                    TYPICAL WORKFLOW\n"
        << "============================================================\n"
        << "\n";

    std::cout
        << "1. Connect to the server.\n"
        << "\n"
        << "2. Type:\n"
        << "     help\n"
        << "   to view this documentation.\n"
        << "\n";

    std::cout
        << "3. Configure SSH protection:\n"
        << "     hardening\n"
        << "\n";

    std::cout
        << "4. Configure brute-force protection:\n"
        << "     security\n"
        << "\n";

    std::cout
        << "5. Configure file monitoring:\n"
        << "     fileguard\n"
        << "\n";

    std::cout
        << "6. Configure Telegram notifications:\n"
        << "     telegram\n"
        << "\n";

    std::cout
        << "7. Manage firewall ports:\n"
        << "     ports\n"
        << "   Open the ports your services need, then enable the\n"
        << "   firewall (see 'How to enable the firewall safely').\n"
        << "\n";

    std::cout
        << "8. Use normal SSH commands when required:\n"
        << "     ls\n"
        << "     pwd\n"
        << "     cd <directory>\n"
        << "\n";

    std::cout
        << "============================================================\n"
        << "                  END OF SERVERGUARD HELP\n"
        << "============================================================\n"
        << "\n";
}