# Anti-Miner

A Windows security tool that automatically detects and terminates cryptocurrency mining processes. It monitors TCP ports, command-line arguments, and uses VirusTotal API to identify and remove miners.

![GIF Demo](https://i.imgur.com/5VoOWY8.gif)

## Features

- 🔍 **Automatic Detection**: Scans for miners every 20 seconds
- 🛡️ **Process Protection**: Self-protects against termination
- 🔐 **VirusTotal Integration**: Uses VirusTotal API for malware detection
- 🚫 **Port Monitoring**: Detects suspicious TCP ports (3333, 4444, 5555, 6666, 7777, 8888, 9999)
- 📝 **Command-Line Analysis**: Scans process arguments for mining-related keywords
- 💻 **Silent Operation**: Runs without console window
- ⚡ **Low Resource Usage**: Minimal CPU and memory footprint
- 📦 **Open Source**: Full source code available

## Detection Methods

The tool uses three detection strategies:

1. **Port-based Detection**: Monitors TCP connections on common mining ports
2. **Argument-based Detection**: Scans process command lines for mining keywords (pool, xmr, monero, eth, minergate, nicehash, mine, mining, money)
3. **VirusTotal Scanning**: Calculates SHA256 hashes of running processes and checks them against VirusTotal database

## Requirements

- Windows OS
- CMake 3.20 or higher (for C++ version)
- Visual Studio with C++ support (for C++ version)
- .NET Framework (for C# version)
- VirusTotal API key (optional, but recommended)

## Building

### C++ Version (CMake)

The repository includes a **full C++ implementation** using Windows/WinAPI with **CMake build system**.

#### Build Instructions

```powershell
cmake -S . -B build
cmake --build build --config Release
```

The executable will be located at `build\Release\anti-miner.exe`.

#### VirusTotal API Key Configuration

For VirusTotal scanning, you need an API key. You can configure it in two ways:

**Option 1 (Recommended)**: Set environment variable `VT_API_KEY`:
```powershell
$env:VT_API_KEY = "your_api_key_here"
```

**Option 2**: Pass the key during CMake configuration:
```powershell
cmake -S . -B build -DVT_API_KEY="your_api_key_here"
cmake --build build --config Release
```

### C# Version

1. Register at [VirusTotal](https://virustotal.com/)
2. Get your API key from Settings
3. Open `Anti-Miner/Program.cs` and replace `"API_KEY"` with your actual API key (line 17)
4. Build the solution in Visual Studio

## Usage

### Running the Application

The application runs silently in the background with no console window. It continuously monitors your system every 20 seconds.

**C++ Version**: Run `build\Release\anti-miner.exe`

**C# Version**: Run the compiled executable from the `Anti-Miner` project

### How It Works

1. The application protects itself from termination
2. Every 20 seconds, it performs three scans:
   - Checks TCP ports for suspicious connections
   - Analyzes process command-line arguments
   - Verifies running processes against VirusTotal
3. When a miner is detected, the process is terminated and its executable file is deleted
4. The cycle repeats indefinitely

## Security Note

⚠️ **Warning**: This tool terminates processes and deletes files. Make sure you understand what it does before using it. False positives are possible, especially with legitimate mining software.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. The authors are not responsible for any damage caused by this software.
