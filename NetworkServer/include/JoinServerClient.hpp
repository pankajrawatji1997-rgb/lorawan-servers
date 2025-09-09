#pragma once
#include <string>
#include <netinet/in.h>

class JoinServerClient {
public:
    JoinServerClient(const std::string &host = "127.0.0.1", int port = 1701);
    ~JoinServerClient();
    bool sendJoinRequest(const std::string &devEUI, const std::string &appEUI, const std::string &devNonce, uint32_t uplink_tmst, const struct sockaddr_in &gwAddr);
private:
    std::string host_;
    int port_;
    int sock_;
    struct sockaddr_in jsAddr_;
};
