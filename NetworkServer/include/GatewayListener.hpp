#pragma once
#include <netinet/in.h>

class NetworkServer;

class GatewayListener {
public:
    GatewayListener(NetworkServer *owner, int port = 1700);
    ~GatewayListener();
    void start();
    void stop();
private:
    void run();
    int sockfd_;
    bool running_;
    NetworkServer *owner_;
    int port_;
};
