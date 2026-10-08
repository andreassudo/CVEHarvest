#include "CVEHarvest.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>

namespace cveh {

    std::string json_quote(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 2);
        for (char ch : s) {
            switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += ch; break;
            }
        }
        return out;
    }

    std::string build_status_json(const std::string& module_name, bool success, const std::string& details) {
        std::ostringstream oss;
        oss << "{"
            << "\"module\":\"" << json_quote(module_name) << "\","
            << "\"success\":" << (success ? "true" : "false") << ","
            << "\"details\":\"" << json_quote(details) << "\""
            << "}";
        return oss.str();
    }

    void Framework::add_module(std::unique_ptr<ExploitModule> module) {
        modules_.push_back(std::move(module));
    }

    std::string Framework::run(const std::vector<TargetSpec>& targets, const PayloadConfig& cfg) {
        std::ostringstream out;
        for (const auto& target : targets) {
            for (auto& mod : modules_) {
                if (mod->supports(target)) {
                    std::string result = mod->execute(target, cfg);
                    out << build_status_json(mod->name(), true, result) << "\n";
                }
            }
        }
        return out.str();
    }
}
