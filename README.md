# System Information Collector Script

This Bash script is designed to gather and display detailed system information on a Unix-like operating system. It outputs various data about the system, such as OS details, user information, system stats, available software, processes, and network configurations. Each function of the script focuses on a specific area of the system and uses color-coded outputs to make it visually easier to read.

## Features

- **Operating System Information**: Displays OS name, version, and distributor ID.
- **User Information**: Shows current user and hostname.
- **System Uptime and Date**: Shows system uptime and current date.
- **System Stats**: Displays disk space usage and memory statistics.
- **CPU Information**: Outputs details about the system's CPU.
- **Environment Variables**: Displays all environment variables.
- **Sudo Version**: Displays the version of sudo installed on the system.
- **Processes and Services**: Lists all running services and system processes.
- **Network Info**: Provides details on network interfaces, open ports, and IP routing.
- **Files Information**: Shows details on important files such as passwords, certificates, Google Chrome installations, etc.
- **MySQL, PostgreSQL, Apache, Nginx**: Provides version information of major services like MySQL, PostgreSQL, Apache, and Nginx if installed.

## Prerequisites

- A Unix-like operating system (Linux/macOS).
- Bash shell for script execution.
- Root privileges may be required for some commands.
- Dependencies (if any) should be installed, such as `mysql`, `psql`, `nginx`, `apache`, etc., depending on what services are being queried.

## Usage

1. **Clone or Download** the script to your system.
2. **Make the script executable**:
   ```bash
   chmod +x system_info.sh
3. **Run Script**:
   ```bash
    ./system_info.sh
  
