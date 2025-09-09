#pragma once
#include <string>
#include <netinet/in.h>

class AppServerClient {
public:
    AppServerClient(const std::string &host = "127.0.0.1", int port = 1703);
    ~AppServerClient();
    void forwardUplink(const std::string &devAddr, const std::string &payloadB64);
private:
    std::string host_;
    int port_;
    int sock_;
    struct sockaddr_in asAddr_;
};