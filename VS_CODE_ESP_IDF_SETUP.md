# ESP-IDF C/C++ Project Configuration

This project is configured for ESP-IDF development with Visual Studio Code.

> **ESP-IDF version:** this project targets **ESP-IDF v6.0.x** (previously v5.4.1 — see [README.md](README.md#2-prerequisites--local-dev-machine-build-firmware--orchestrate-tests) for details on the migration, including the `json`/`mqtt` → IDF Component Manager change and the PSA Crypto migration for the crypto helpers). Make sure `idf.espIdfPath` in `.vscode/settings.json` points at a v6.0.x checkout.

## Created Configurations

### VS Code Configuration Files:
- `.vscode/c_cpp_properties.json` - C/C++ IntelliSense configuration
- `.vscode/tasks.json` - Tasks for build, flash, and monitor
- `.vscode/launch.json` - Debug configuration
- `.vscode/settings.json` - Workspace settings
- `.vscode/extensions.json` - Recommended extensions

### Recommended Extensions:
- **ESP-IDF Extension** - Official Espressif extension for ESP-IDF
- **C/C++ Extension Pack** - Complete C/C++ support
- **CMake Tools** - CMake support
- **Serial Monitor** - Integrated serial monitor
- **Cortex-Debug** - Debug support for ARM microcontrollers

## How to Use

### 1. Install Extensions
VS Code should automatically suggest installing the recommended extensions.

### 2. Build Project
- **Ctrl+Shift+P** → "Tasks: Run Task" → "Build - ESP-IDF"
- Or use **Ctrl+Shift+B** for quick build

### 3. Flash Firmware
- **Ctrl+Shift+P** → "Tasks: Run Task" → "Flash - ESP-IDF"
- Make sure the COM port is correct in `.vscode/settings.json` (currently COM3)

### 4. Serial Monitor
- **Ctrl+Shift+P** → "Tasks: Run Task" → "Monitor - ESP-IDF"

### 5. Project Configuration
- **Ctrl+Shift+P** → "Tasks: Run Task" → "Configure - ESP-IDF"

### 6. Debugging (requires hardware debugger)
- **F5** to start debugging
- Requires OpenOCD configured and hardware debugger connected

## Support Scripts

### `setup_esp_env.bat`
Script to open a terminal with ESP-IDF environment configured:
```cmd
./setup_esp_env.bat
```

This script:
1. Configures ESP-IDF environment
2. Makes all `idf.py` commands available
3. Keeps the terminal open for subsequent commands

## Port Configuration

The serial port is configured as **COM3** in `.vscode/settings.json`. 
To change it, modify this line:
```json
"idf.port": "COM3"
```

## Troubleshooting

### If IntelliSense doesn't work:
1. Verify the project has been built at least once
2. Check that `build/compile_commands.json` exists
3. Reload VS Code

### If build tasks fail:
1. Use the `setup_esp_env.bat` script to verify the environment
2. Check that ESP-IDF is properly installed
3. Verify paths in `.vscode/settings.json`

### To update toolchain paths:
If you update ESP-IDF or the toolchain, update these files:
- `.vscode/c_cpp_properties.json` (compilerPath)
- `.vscode/settings.json` (C_Cpp.default.compilerPath)
- `.vscode/launch.json` (miDebuggerPath)
