#include "Help.h"

#include <iostream>


// ============================================================
// SHOW HELP
// ============================================================

void showHelp()
{
    std::cout
        << "\n"
        << "============================================================\n"
        << "                     SERVERGUARD HELP\n"
        << "============================================================\n"
        << "\n";


    // ========================================================
    // GENERAL COMMANDS
    // ========================================================

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


    // ========================================================
    // SECURITY
    // ========================================================

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


    // ========================================================
    // FILE GUARD
    // ========================================================

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


    // ========================================================
    // SSH HARDENING
    // ========================================================

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


    // ========================================================
    // TELEGRAM BOT
    // ========================================================

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


    // ========================================================
    // SERVERGUARD MODULES
    // ========================================================

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


    // ========================================================
    // IMPORTANT PATHS
    // ========================================================

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


    // ========================================================
    // SERVICES
    // ========================================================

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


    // ========================================================
    // TYPICAL WORKFLOW
    // ========================================================

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
        << "7. Use normal SSH commands when required:\n"
        << "     ls\n"
        << "     pwd\n"
        << "     cd <directory>\n"
        << "\n";


    // ========================================================
    // END
    // ========================================================

    std::cout
        << "============================================================\n"
        << "                  END OF SERVERGUARD HELP\n"
        << "============================================================\n"
        << "\n";
}