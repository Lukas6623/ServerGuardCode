<div align="center">

# 🛡️ ServerGuard

### Open-source security and server management platform for Linux

Protect, monitor and manage your Linux servers from Windows.

<br>

[![Version](https://img.shields.io/github/v/release/Lukas6623/ServerGuard?style=for-the-badge&logo=github&label=Version)](https://github.com/Lukas6623/ServerGuard/releases/latest)
[![Stars](https://img.shields.io/github/stars/Lukas6623/ServerGuard?style=for-the-badge&logo=github)](https://github.com/Lukas6623/ServerGuard/stargazers)
[![Issues](https://img.shields.io/github/issues/Lukas6623/ServerGuard?style=for-the-badge&logo=github)](https://github.com/Lukas6623/ServerGuard/issues)
[![License](https://img.shields.io/github/license/Lukas6623/ServerGuard?style=for-the-badge&logo=github)](https://github.com/Lukas6623/ServerGuard/blob/main/LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-ServerGuard%20Channel-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/server_guard_channel)

<br><br>

<a href="https://github.com/Lukas6623/ServerGuard/releases/latest">
<img src="https://img.shields.io/badge/⬇%20DOWNLOAD%20SERVERGUARD%20SETUP-2ea44f?style=for-the-badge&logo=windows&logoColor=white">
</a>

<br><br>

**Windows 10 / Windows 11**

</div>

---

# 📖 About

**ServerGuard** is an open-source security and server management platform
designed to help users monitor, protect and manage Linux servers.

The project combines a Windows desktop application with lightweight
security modules that run directly on the Linux server.

ServerGuard focuses on server protection, SSH security, brute-force
detection, file protection, SSH hardening and security notifications.

The project is designed for system administrators, developers, students
and anyone interested in Linux server security and automation.

---

# ✨ Features

<table>
<tr>

<td width="50%" valign="top">

## 🔐 SSH Security

- SSH connection management
- SSH login monitoring
- Successful login detection
- Failed login detection
- Invalid user detection
- SSH hardening
- Remote SSH commands
- SFTP support

</td>

<td width="50%" valign="top">

## 🛡️ Brute-Force Protection

- Failed authentication monitoring
- Automatic IP blocking
- UFW integration
- Temporary IP blocks
- Permanent IP blocks
- IP whitelist
- Security event logging

</td>

</tr>

<tr>

<td width="50%" valign="top">

## 📁 File Protection

- File integrity monitoring
- Protected file monitoring
- File change detection
- Security event logging
- Automatic protection service
- Remote module updates

</td>

<td width="50%" valign="top">

## 📱 Notifications

- Telegram notifications
- SSH security alerts
- Brute-force alerts
- File protection alerts
- Server security events
- Windows notifications

</td>

</tr>

<tr>

<td width="50%" valign="top">

## 🖥️ Windows Application

- C++ application
- SSH/SFTP connection
- Remote Linux server management
- Security management
- Module management
- Server monitoring
- Windows system notifications

</td>

<td width="50%" valign="top">

## ⚙️ Automatic Updates

- Version checking
- Module updates
- Application updates
- SHA-256 verification
- Backup before update
- Automatic installation
- Update recovery

</td>

</tr>
</table>

---

# 🧩 Project Components

ServerGuard consists of several components.

```text
┌─────────────────────────────────────────────┐
│                  ServerGuard                │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │       Windows Application             │  │
│  │             C++ / libssh2             │  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│                SSH / SFTP                   │
│                      │                      │
│                      ▼                      │
│  ┌───────────────────────────────────────┐  │
│  │          Linux Server                 │  │
│  │                                       │  │
│  │  ┌──────────────┐ ┌────────────────┐  │  │
│  │  │ FileGuard    │ │ Brute Force    │  │  │
│  │  │              │ │ Guard          │  │  │
│  │  └──────────────┘ └────────────────┘  │  │
│  │                                       │  │
│  │  ┌──────────────┐ ┌────────────────┐  │  │
│  │  │ SSH Monitor  │ │ SSH Hardening  │  │  │
│  │  └──────────────┘ └────────────────┘  │  │
│  │                                       │  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│                      ▼                      │
│              Telegram Notifications         │
└─────────────────────────────────────────────┘
