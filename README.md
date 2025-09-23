# ssflow

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![GoDoc](https://img.shields.io/badge/godoc-reference-blue)
![License](https://img.shields.io/badge/license-MIT-blue)

## 🚀 Overview

ssflow is a Go-based application designed to capture network session events (TCP SYN/FIN/RST packets), enrich them with associated process names, and export the data as IPFIX messages. This tool is ideal for network monitoring, security analysis, and understanding application-level network behavior.

## ✨ Features

*   **Session Event Capture:** Monitors network traffic for TCP SYN (session start), FIN, and RST (session end) packets.
*   **Process Name Enrichment:** Identifies and associates the process name responsible for the network connection.
*   **IPFIX Export:** Formats captured session data into IPFIX messages for compatibility with network flow collectors.
*   **Cross-Platform Compatibility:** Supports building for Linux and Windows.
*   **Configurable:** Easy-to-use YAML configuration for network interface, BPF filters, and IPFIX collector settings.

## 📦 Installation

### Prerequisites

*   **Go Language:** Go 1.20 or newer.

### Go Modules

This project uses Go modules for dependency management. The `make build` command will automatically download the necessary modules.

### System Dependencies

*   **Packet Capture Library:**
    *   **Linux:** `libpcap` (usually installed with `tcpdump` or `wireshark`).
        ```bash
        sudo apt-get install libpcap-dev  # Debian/Ubuntu
        sudo yum install libpcap-devel   # CentOS/RHEL
        ```
    *   **Windows:** `Npcap` (recommended) or `WinPcap`. Ensure you install the **developer's pack** version if prompted, as it provides necessary headers and libraries.
*   **Python 3:** Required for running the `ipfix_decoder.py` test utility.

### Clone the Repository

```bash
git clone https://github.com/sfreet/ssflow.git
cd ssflow
```

### Build the Application

Use `make` to build the project. This will also fetch Go module dependencies.

*   **For Linux (your current OS):**
    ```bash
    make build
    # Output: ./ssflow
    ```

*   **For Windows (cross-compile from Linux):**
    ```bash
    make build-windows
    # Output: ./ssflow.exe
    ```

*   **Note on `build-nocgo`:** The `Makefile` includes a `build-nocgo` target. However, `ssflow` relies on `gopacket` which uses CGO (C interoperability) for `libpcap` bindings. Therefore, `make build-nocgo` will fail. This target is included for demonstration purposes of a common Go build option.


## ⚙️ Configuration

The application uses a `config.yaml` file for its settings. An example configuration file, `config.example.yaml`, is provided in the repository.

To get started, copy `config.example.yaml` to `config.yaml` and modify it according to your environment:

```bash
cp config.example.yaml config.yaml
# Then, open config.yaml in your favorite editor and adjust the settings.
```

Here's the content of `config.example.yaml`:

```yaml
# config.example.yaml

# Network interface to capture packets from
# Linux: e.g., "eth0", "enp0s3", "any"
# Windows: e.g., "\Device\NPF_{GUID}" or a descriptive name if Npcap supports it.
# IMPORTANT: Replace with your actual network interface.
interface: "any" # Example: "eth0" or "enp0s3" on Linux, or a descriptive name on Windows

# BPF filter settings
bpf:
  # Source host to filter. Leave empty (" ") to capture from all hosts.
  # Example: "192.168.1.100"
  # IMPORTANT: Replace with your desired source host or leave empty.
  source_host: "" # Example: "192.168.1.100"

# IPFIX collector settings
collector:
  host: "127.0.0.1"
  port: 4739

# Exporter settings
exporter:
  # Interval in seconds to export data
  interval_seconds: 5
  # Number of events per chunk
  chunk_size: 20
```

## 🚀 Usage

After building and configuring, run the application from your terminal:

```bash
sudo ./ssflow # On Linux
# or
.\ssflow.exe # On Windows (run as Administrator)
```

## 🧪 Testing

This project includes a simple Python script (`ipfix_decoder.py`) to help test the IPFIX export functionality. This script listens on UDP port 4739 (the default IPFIX collector port) and decodes incoming IPFIX messages, printing the session events in a human-readable format.

### Running the IPFIX Decoder

First, start the Python decoder:

```bash
python3 ipfix_decoder.py
```

### Running `ssflow` and Observing Output

In a separate terminal, run the `ssflow` application (ensure it's configured to send to `127.0.0.1:4739`):

```bash
sudo ./ssflow
```

You should see decoded IPFIX messages appearing in the terminal where `ipfix_decoder.py` is running.

### Running Go Tests

To run the unit tests for the Go application:

```bash
make test
```


## 🤝 Contributing

Contributions are welcome! Please feel free to open issues, submit pull requests, or suggest improvements.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ❓ Support

For any questions or issues, please open an issue on the GitHub repository.
