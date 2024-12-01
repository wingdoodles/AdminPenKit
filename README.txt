# AdminPenKit - Cross-Platform System Administration & Security Tool

A powerful GUI-based toolkit for system administrators and security professionals, compatible with Windows, Linux, and MacOS.

## Features
- System Information Gathering
- Network Scanning
- Service Management
- Security Auditing

## Installation

### Windows
1. Install Python 3.8 or higher from python.org
2. Clone the repository:
   git clone https://github.com/yourusername/adminpenkit.git
   cd adminpenkit
3. Install dependencies:
   pip install -r requirements/requirements_windows.txt

### Linux
1. Install system dependencies:
   # Debian/Ubuntu
   sudo apt-get update
   sudo apt-get install python3 python3-pip python3-tk python3-dev

   # Fedora
   sudo dnf install python3 python3-pip python3-tkinter python3-devel

   # Arch Linux
   sudo pacman -S python python-pip tk

2. Clone the repository:
   git clone https://github.com/yourusername/adminpenkit.git
   cd adminpenkit

3. Install Python dependencies:
   pip install -r requirements/requirements_linux.txt

### MacOS
1. Install Homebrew if not already installed:
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

2. Install Python and dependencies:
   brew install python python-tk

3. Clone the repository:
   git clone https://github.com/yourusername/adminpenkit.git
   cd adminpenkit

4. Install Python dependencies:
   pip install -r requirements/requirements_macos.txt

## Usage
1. Launch the application:
   python adminpenkit/main.py

2. Using the Interface:
   - System Information: Click the "System Info" tab to view detailed system specifications
   - Network Scanner: Enter target IP in the "Network Scanner" tab and click "Scan"
   - Service Manager: View and manage system services from the "Services" tab

## Tool Modules

### System Information
- Hardware Details
- Operating System Information
- Memory Usage
- Disk Space
- CPU Statistics

### Network Scanner
- IP Scanning
- Port Scanning
- Service Detection
- Network Mapping

### Service Manager
- List Running Services
- Start/Stop Services
- Service Status Monitoring
- Service Configuration

## Security Features
- Port Security Scanning
- Service Vulnerability Detection
- System Security Audit
- Permission Analysis

## Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
MIT License - See LICENSE file for details

## Support
- GitHub Issues: Report bugs and feature requests
- Documentation: Available in the /docs directory
- Wiki: Check our GitHub wiki for detailed guides

## Requirements
- Python 3.8+
- Operating System: Windows 10+, Linux (Modern Distributions), MacOS 10.15+
- RAM: 2GB minimum
- Storage: 100MB free space

## Updates
Check the releases page for latest versions and updates.
