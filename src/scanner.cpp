#include "CVEHarvest.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace cveh {

    std::vector<TargetSpec> Scanner::parse_targets_from_file(const std::string& path) {
        std::ifstream in(path);
        std::vector<TargetSpec> targets;
        if (!in) return targets;
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty() || line.rfind("#", 0) == 0) continue;
            TargetSpec t;
            t.host = line;
            t.port = 445;
            t.protocol = "smb";
            targets.push_back(t);
        }
        return targets;
    }

    std::vector<ProbeResult> Scanner::sweep(const std::vector<TargetSpec>& targets) {
        std::vector<ProbeResult> results;
        for (const auto& t : targets) {
            ProbeResult r;
            r.host = t.host;

            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) continue;

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(t.port);
            if (inet_pton(AF_INET, t.host.c_str(), &addr.sin_addr) != 1) {
                closesocket(s);
                continue;
            }

            u_long mode = 1;
            ioctlsocket(s, FIONBIO, &mode);

            int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            int err = WSAGetLastError();
            if (rc == 0 || err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                r.reachable = true;
            }

            if (r.reachable) {
                char buffer[512] = {};
                int n = recv(s, buffer, sizeof(buffer) - 1, 0);
                if (n > 0) {
                    r.banner = std::string(buffer, n);
                    std::transform(r.banner.begin(), r.banner.end(), r.banner.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    r.http = r.banner.find("http") != std::string::npos;
                    r.smb = r.banner.find("smb") != std::string::npos || r.banner.find("windows") != std::string::npos;
                    r.msrpc = r.banner.find("rpc") != std::string::npos;
                    r.winrm = r.banner.find("winrm") != std::string::npos;
                }
            }

            closesocket(s);
            results.push_back(r);
        }
        return results;
    }

}
