<div align="center">

# 🛡️ ServerGuard

### Open-source security and server management platform for Linux

Protect, monitor and manage your Linux servers from a Windows application.

<br>

[![GitHub release](https://img.shields.io/github/v/release/Lukas6623/ServerGuard?style=for-the-badge&logo=github&label=Latest%20Release)](https://github.com/Lukas6623/ServerGuard/releases)
[![GitHub stars](https://img.shields.io/github/stars/Lukas6623/ServerGuard?style=for-the-badge&logo=github)](https://github.com/Lukas6623/ServerGuard/stargazers)
[![GitHub license](https://img.shields.io/github/license/Lukas6623/ServerGuard?style=for-the-badge)](https://github.com/Lukas6623/ServerGuard/blob/main/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/Lukas6623/ServerGuard?style=for-the-badge&logo=github)](https://github.com/Lukas6623/ServerGuard/issues)

<br>

<a href="https://github.com/Lukas6623/ServerGuard/releases">
  <img src="https://img.shields.io/badge/Download-Latest%20Release-2ea44f?style=for-the-badge">
</a>

</div>

---

## 📖 About

**ServerGuard** is an open-source security and server management platform designed
to help users monitor, protect and manage Linux servers.

The project consists of a Windows desktop application and a collection of
lightweight security modules that run directly on the Linux server.

ServerGuard is designed with a **protection-first approach**, providing tools
for SSH monitoring, brute-force protection, file protection, SSH hardening
and server notifications.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔐 SSH Security

- SSH login monitoring
- Failed login detection
- Successful login detection
- Invalid user detection
- SSH hardening
- Remote SSH management

</td>

<td width="50%">

### 🛡️ Brute-Force Protection

- Failed login detection
- Automatic IP blocking
- UFW integration
- Temporary and permanent blocks
- IP whitelist support
- Security event logging

</td>
</tr>

<tr>
<td width="50%">

### 📁 File Protection

- File integrity monitoring
- File change detection
- Protected files
- Security events
- Automatic protection service

</td>

<td width="50%">

### 📱 Notifications

- Telegram notifications
- SSH security alerts
- Brute-force alerts
- File protection alerts
- Server security events

</td>
</tr>

<tr>
<td width="50%">

### 🖥️ Windows Application

- SSH/SFTP connection
- Remote server management
- Security management
- Module management
- Server monitoring
- Windows notifications

</td>

<td width="50%">

### ⚙️ Automatic Updates

- Module updates
- Version checking
- Backup before update
- Automatic installation
- SHA-256 verification
- Update rollback support

</td>
</tr>
</table>

---

# 🏗️ Architecture

ServerGuard uses a client/server-style architecture.

```text
                    ┌─────────────────────────┐
                    │      Windows PC         │
                    │                         │
                    │      ServerGuard        │
                    │        C++ App          │
                    │                         │
                    └────────────┬────────────┘
                                 │
                         SSH / SFTP / Commands
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Linux Server       │
                    │                         │
                    │   ┌─────────────────┐   │
                    │   │ Security Modules│   │
                    │   └─────────────────┘   │
                    │                         │
                    │   ┌─────────────────┐   │
                    │   │   FileGuard     │   │
                    │   └─────────────────┘   │
                    │                         │
                    │   ┌─────────────────┐   │
                    │   │ Brute Force     │   │
                    │   │ Guard           │   │
                    │   └─────────────────┘   │
                    │                         │
                    │   ┌─────────────────┐   │
                    │   │ SSH Hardening   │   │
                    │   └─────────────────┘   │
                    │                         │
                    └────────────┬────────────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │   Telegram    │
                         │ Notifications │
                         └───────────────┘
